import { Pool } from 'pg';
import type { AuthAssembly } from '../auth/auth-config';
import type { AuthenticationProvider } from '../auth/authentication-provider';
import type { AuthService } from '../auth/auth.service';
import type { LoginThrottle } from '../auth/login-throttle';
import { generateErasureSalt } from '../crypto/person-identity';
import { generatePublicIdentifier } from './public-identifier';

export type RegisterResult =
  | { outcome: 'THROTTLED' }
  | { outcome: 'SECRET_TOO_SHORT'; minLength: number }
  | {
      outcome: 'OK';
      identifier: string;
      accountId: string;
      personId: string;
      accessToken: string;
      accessTokenExpiresAt: Date;
      refreshToken: string;
    };

export const REGISTRATION_SERVICE = 'REGISTRATION_SERVICE';

// Chaque identifiant sort d'un CSPRNG sur ~9 × 10⁹ valeurs : une collision est
// rarissime, cinq tirages la rendent astronomiquement improbable. Au-delà,
// quelque chose d'autre est cassé — on échoue BRUYAMMENT, on ne boucle pas.
const MAX_IDENTIFIER_DRAWS = 5;

/**
 * L'inscription publique (LOT 4, refondue au LOT 5) : la PERSONNE, le compte
 * et son premier secret naissent ensemble par create_account() — LE chemin
 * unique (011/016) — dans la même transaction. Les DEUX identifiants publics
 * (compte, personne) sont GÉNÉRÉS par nous (CSPRNG) : aucune énumération,
 * personne ne « choisit » un identifiant déjà pris. Le sel d'effacement de la
 * personne naît ici aussi (CSPRNG, 32 octets) — l'identité civile, elle,
 * se fournit plus tard (endpoint dédié) : minimisation, rien « au cas où ».
 *
 * Throttle par IP SEULE, budget distinct du login. Zéro PII : ce service ne
 * logge rien, les identifiants rendus ne sont ni des numéros ni des noms.
 */
export class RegistrationService {
  constructor(
    private readonly pool: Pool,
    private readonly provider: AuthenticationProvider,
    private readonly auth: AuthService,
    private readonly config: AuthAssembly,
    private readonly throttle: LoginThrottle,
    // Injectables pour prouver le re-tirage sur collision (tests) — le défaut
    // est LE générateur du dépôt, pour les deux espaces d'identifiants.
    private readonly generateIdentifier: () => string = generatePublicIdentifier,
    private readonly generatePersonIdentifier: () => string = generatePublicIdentifier,
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

    let created: { accountId: string; personId: string } | null = null;
    let identifier = this.generateIdentifier();
    let personIdentifier = this.generatePersonIdentifier();
    for (let draw = 0; draw < MAX_IDENTIFIER_DRAWS && created === null; draw += 1) {
      try {
        const result = await this.pool.query<{ account_id: string; person_id: string }>(
          `SELECT account_id, person_id
             FROM create_account($1, 'ACCOUNT_HOLDER', $2, false, NULL, $3, $4)`,
          [identifier, secretHash, personIdentifier, generateErasureSalt()],
        );
        const row = result.rows[0];
        created = row === undefined ? null : { accountId: row.account_id, personId: row.person_id };
      } catch (err) {
        // On ne re-tire QUE l'identifiant en collision : l'unicité est
        // tranchée par la base (deux registres, deux contraintes), pas ici.
        const collision = collidedConstraint(err);
        if (collision === 'uq_accounts_public_identifier') {
          identifier = this.generateIdentifier();
          continue;
        }
        if (collision === 'uq_persons_public_identifier') {
          personIdentifier = this.generatePersonIdentifier();
          continue;
        }
        throw err;
      }
    }
    if (created === null) {
      throw new Error('inscription : identifiant unique introuvable après plusieurs tirages');
    }

    // La première session naît par le MÊME chemin que le login (aucune
    // deuxième écriture du patron de session).
    const session = await this.auth.openSession(created.accountId);
    const issued = await this.provider.issueAccessToken({
      sub: created.accountId,
      sid: session.sessionId,
    });
    return {
      outcome: 'OK',
      identifier,
      accountId: created.accountId,
      personId: created.personId,
      accessToken: issued.token,
      accessTokenExpiresAt: issued.expiresAt,
      refreshToken: session.refreshToken,
    };
  }
}

function collidedConstraint(err: unknown): string | null {
  if (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    (err as { code?: unknown }).code === '23505' &&
    'constraint' in err
  ) {
    const { constraint } = err as { constraint?: unknown };
    return typeof constraint === 'string' ? constraint : null;
  }
  return null;
}
