import { Pool } from 'pg';
import type { AuthAssembly } from '../auth/auth-config';
import type { AuthenticationProvider } from '../auth/authentication-provider';
import type { AuthService } from '../auth/auth.service';
import type { LoginThrottle } from '../auth/login-throttle';
import { generatePublicIdentifier } from './public-identifier';

export type RegisterResult =
  | { outcome: 'THROTTLED' }
  | { outcome: 'SECRET_TOO_SHORT'; minLength: number }
  | {
      outcome: 'OK';
      identifier: string;
      accountId: string;
      accessToken: string;
      accessTokenExpiresAt: Date;
      refreshToken: string;
    };

export const REGISTRATION_SERVICE = 'REGISTRATION_SERVICE';

// L'identifiant sort d'un CSPRNG sur ~9 × 10⁹ valeurs : une collision est
// rarissime, cinq tirages la rendent astronomiquement improbable. Au-delà,
// quelque chose d'autre est cassé — on échoue BRUYAMMENT, on ne boucle pas.
const MAX_IDENTIFIER_DRAWS = 5;

/**
 * L'inscription publique (LOT 4) : le compte naît par create_account() —
 * LE chemin unique (011) — avec son premier secret, dans la même
 * transaction. L'identifiant est GÉNÉRÉ par nous (CSPRNG) : aucune
 * énumération d'identifiants possible, personne ne « choisit » un
 * identifiant déjà pris (donc aucun oracle d'existence par l'inscription).
 *
 * Throttle par IP SEULE, budget distinct du login. Zéro PII : ce service ne
 * logge rien, l'identifiant rendu n'est ni un numéro ni un nom.
 */
export class RegistrationService {
  constructor(
    private readonly pool: Pool,
    private readonly provider: AuthenticationProvider,
    private readonly auth: AuthService,
    private readonly config: AuthAssembly,
    private readonly throttle: LoginThrottle,
    // Injectable pour prouver le re-tirage sur collision (tests) — le défaut
    // est LE générateur du dépôt.
    private readonly generateIdentifier: () => string = generatePublicIdentifier,
  ) {}

  async register(secret: string, clientIp: string): Promise<RegisterResult> {
    if (!this.throttle.allowByKey(clientIp)) {
      return { outcome: 'THROTTLED' };
    }
    // Façade (§3.1) : une erreur PROPRE avant le coût argon2. Le mur porteur
    // du secret (forme argon2id, un seul ACTIVE) reste en base.
    if (secret.length < this.config.secretMinLength) {
      return { outcome: 'SECRET_TOO_SHORT', minLength: this.config.secretMinLength };
    }

    const secretHash = await this.provider.hashSecret(secret);

    let accountId: string | null = null;
    let identifier = '';
    for (let draw = 0; draw < MAX_IDENTIFIER_DRAWS && accountId === null; draw += 1) {
      identifier = this.generateIdentifier();
      try {
        const created = await this.pool.query<{ id: string }>(
          "SELECT create_account($1, 'ACCOUNT_HOLDER', $2, false, NULL) AS id",
          [identifier, secretHash],
        );
        accountId = created.rows[0]?.id ?? null;
      } catch (err) {
        if (isIdentifierCollision(err)) {
          continue; // re-tirage : l'unicité est tranchée par la base, pas ici
        }
        throw err;
      }
    }
    if (accountId === null) {
      throw new Error('inscription : identifiant unique introuvable après plusieurs tirages');
    }

    // La première session naît par le MÊME chemin que le login (aucune
    // deuxième écriture du patron de session).
    const session = await this.auth.openSession(accountId);
    const issued = await this.provider.issueAccessToken({ sub: accountId, sid: session.sessionId });
    return {
      outcome: 'OK',
      identifier,
      accountId,
      accessToken: issued.token,
      accessTokenExpiresAt: issued.expiresAt,
      refreshToken: session.refreshToken,
    };
  }
}

function isIdentifierCollision(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    (err as { code?: unknown }).code === '23505' &&
    'constraint' in err &&
    (err as { constraint?: unknown }).constraint === 'uq_accounts_public_identifier'
  );
}
