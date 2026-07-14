import { createHash, randomBytes, randomUUID } from 'crypto';
import { Pool } from 'pg';
import { DB_ERROR, isDbError } from '../db/errors';
import type { AuthAssembly } from './auth-config';
import type { AuthenticationProvider } from './authentication-provider';
import type { LocalAuthenticationProvider } from './local-authentication-provider';
import type { LoginThrottle } from './login-throttle';

export type LoginResult =
  | { outcome: 'THROTTLED' }
  | { outcome: 'FAILED' }
  | {
      outcome: 'OK';
      accessToken: string;
      accessTokenExpiresAt: Date;
      refreshToken: string;
      mustChangeSecret: boolean;
    };

interface AccountRow {
  id: string;
  status: string;
}

interface AuthenticableSecretRow {
  id: string;
  secret_hash: string;
  is_temporary: boolean;
}

/**
 * Le login. Trois propriétés, prouvées par les tests :
 *   1. EXACTEMENT UNE vérification argon2 par tentative, sur TOUS les
 *      chemins (inconnu, désactivé, verrouillé, expiré, mauvais secret,
 *      succès) — l'échec est indiscernable au chrono comme au message (C3).
 *   2. Le service ne lit un hash que par la vue authenticable_secrets (C9) :
 *      un compte verrouillé ou un secret mort n'ont structurellement AUCUN
 *      hash à vérifier — c'est le chemin « référence » qui s'exécute.
 *   3. Aucune PII dans les logs : ce service ne logge RIEN (counts et enums
 *      remontent par les résultats, pas par la console).
 */
export class AuthService {
  constructor(
    private readonly pool: Pool,
    private readonly provider: AuthenticationProvider,
    private readonly local: LocalAuthenticationProvider,
    private readonly config: AuthAssembly,
    private readonly throttle: LoginThrottle,
  ) {}

  async login(identifier: string, secret: string, clientIp: string): Promise<LoginResult> {
    if (!this.throttle.allow(clientIp, identifier)) {
      // Refusé AVANT tout coût argon2 : le throttle est le plafond de débit.
      return { outcome: 'THROTTLED' };
    }

    const account = await this.findActiveAccount(identifier);
    const secretRow = account === null ? null : await this.findAuthenticableSecret(account.id);

    if (secretRow === null) {
      // C3 : même coût que le chemin nominal — une vérification, ni plus ni
      // moins — contre le hash de référence. Puis le même échec générique.
      await this.provider.verifySecret(this.local.getReferenceHash(), secret);
      return { outcome: 'FAILED' };
    }

    const verified = await this.provider.verifySecret(secretRow.secret_hash, secret);
    if (!verified) {
      await this.registerFailure(secretRow.id);
      return { outcome: 'FAILED' };
    }

    await this.pool.query(
      'UPDATE account_secrets SET failed_attempts = 0 WHERE id = $1 AND failed_attempts > 0',
      [secretRow.id],
    );

    const session = await this.openSession(account!.id);
    const issued = await this.provider.issueAccessToken({ sub: account!.id, sid: session.sessionId });
    return {
      outcome: 'OK',
      accessToken: issued.token,
      accessTokenExpiresAt: issued.expiresAt,
      refreshToken: session.refreshToken,
      mustChangeSecret: secretRow.is_temporary,
    };
  }

  private async findActiveAccount(identifier: string): Promise<AccountRow | null> {
    const result = await this.pool.query<AccountRow>(
      "SELECT id, status FROM accounts WHERE public_identifier = $1 AND status = 'ACTIVE'",
      [identifier],
    );
    return result.rows[0] ?? null;
  }

  private async findAuthenticableSecret(accountId: string): Promise<AuthenticableSecretRow | null> {
    // C9 : la vue est le SEUL chemin vers un hash — et elle ne montre que le
    // vivant (ACTIVE, non expiré, non verrouillé).
    const result = await this.pool.query<AuthenticableSecretRow>(
      'SELECT id, secret_hash, is_temporary FROM authenticable_secrets WHERE account_id = $1',
      [accountId],
    );
    return result.rows[0] ?? null;
  }

  private async registerFailure(secretId: string): Promise<void> {
    const result = await this.pool.query<{ failed_attempts: number }>(
      'UPDATE account_secrets SET failed_attempts = failed_attempts + 1 WHERE id = $1 RETURNING failed_attempts',
      [secretId],
    );
    const failures = result.rows[0]?.failed_attempts ?? 0;
    if (failures < this.config.lockThreshold) {
      return;
    }
    // Backoff progressif : base × 2^(échecs − seuil), plafonné (config, C7/C8).
    const exponent = failures - this.config.lockThreshold;
    const backoffSeconds = Math.min(
      this.config.lockBaseSeconds * 2 ** exponent,
      this.config.lockCapSeconds,
    );
    try {
      await this.pool.query(
        'UPDATE account_secrets SET locked_until = now() + make_interval(secs => $2) WHERE id = $1',
        [secretId, backoffSeconds],
      );
    } catch (err) {
      // Course rarissime : un verrou futur plus long existe déjà — le trigger
      // C8 refuse le recul, et c'est exactement ce qu'on veut. On reconnaît
      // ce refus par son CODE (migration 005), jamais par son message : un
      // message se reformule, un code est un contrat.
      if (!isDbError(err, DB_ERROR.LOCK_WOULD_RECEDE)) {
        throw err;
      }
    }
  }

  private async openSession(
    accountId: string,
  ): Promise<{ sessionId: string; refreshToken: string }> {
    // La valeur du jeton ne touche JAMAIS la base : seul son SHA-256 y entre
    // (§3.6). 256 bits d'entropie CSPRNG — pas de sel nécessaire pour un
    // secret non humain.
    const refreshToken = randomBytes(32).toString('base64url');
    const tokenHash = createHash('sha256').update(refreshToken, 'utf8').digest('hex');

    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const session = await client.query<{ id: string; absolute_expires_at: string }>(
        `INSERT INTO sessions (account_id, absolute_expires_at)
         VALUES ($1, now() + make_interval(secs => $2))
         RETURNING id, absolute_expires_at`,
        [accountId, this.config.sessionAbsoluteTtlSeconds],
      );
      const sessionId = session.rows[0]?.id;
      const absoluteExpiresAt = session.rows[0]?.absolute_expires_at;
      if (sessionId === undefined || absoluteExpiresAt === undefined) {
        throw new Error('création de session : aucune ligne rendue');
      }
      // C10-b côté service : le jeton n'excède jamais l'échéance de session.
      await client.query(
        `INSERT INTO session_refresh_tokens (session_id, jti, token_hash, expires_at)
         VALUES ($1, $2, $3, LEAST(now() + make_interval(secs => $4), $5::timestamptz))`,
        [sessionId, randomUUID(), tokenHash, this.config.refreshTokenTtlSeconds, absoluteExpiresAt],
      );
      await client.query('COMMIT');
      return { sessionId, refreshToken };
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }
}
