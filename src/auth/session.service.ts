import { createHash, randomBytes, randomUUID } from 'crypto';
import { Pool, PoolClient } from 'pg';
import type { AuthAssembly } from './auth-config';
import type { AuthenticationProvider } from './authentication-provider';
import type { LoginThrottle } from './login-throttle';

export type RefreshResult =
  | { outcome: 'THROTTLED' }
  | { outcome: 'REFUSED' }
  | { outcome: 'REPLAY_DETECTED' }
  | {
      outcome: 'OK';
      accessToken: string;
      accessTokenExpiresAt: Date;
      /** Absent = le client conserve le jeton de rafraîchissement qu'il a déjà. */
      refreshToken?: string;
    };

export type RevokeResult = { outcome: 'OK'; revokedSessions: number } | { outcome: 'REFUSED' };

export const SESSION_SERVICE = 'SESSION_SERVICE';

interface Verdict {
  token_id: string | null;
  session_id: string | null;
  account_id: string | null;
  successor_id: string | null;
  verdict: string;
}

/**
 * Sessions : rotation, rejeu, grâce, révocation serveur.
 *
 * LA règle de ce fichier : il n'écrit AUCUN « WHERE status = … » sur les
 * jetons et ne compare AUCUN hash. Il appelle lookup_refresh_token (C10) et
 * agit sur le VERDICT rendu par la base :
 *   USABLE → rotation atomique · GRACE → rendre le successeur DÉJÀ émis
 *   REPLAY → révoquer TOUTE la session · DEAD/UNKNOWN → refus sec.
 *
 * La fenêtre de grâce n'émet JAMAIS un nouveau jeton : elle rejoue le
 * successeur existant (sinon deux requêtes concurrentes d'un mobile sur
 * réseau instable fabriqueraient deux jetons — la grâce deviendrait une
 * fabrique).
 *
 * Ce qui n'est PAS garanti (C2, dit honnêtement) : un jeton d'ACCÈS déjà
 * émis reste valide jusqu'à son expiration — au plus 15 min (borne dure au
 * boot). La révocation est immédiate pour le refresh et la session.
 */
export class SessionService {
  constructor(
    private readonly pool: Pool,
    private readonly provider: AuthenticationProvider,
    private readonly config: AuthAssembly,
    private readonly throttle: LoginThrottle,
  ) {}

  private hashOf(token: string): string {
    return createHash('sha256').update(token, 'utf8').digest('hex');
  }

  private async lookup(client: Pool | PoolClient, token: string): Promise<Verdict> {
    const result = await client.query<Verdict>('SELECT * FROM lookup_refresh_token($1)', [
      this.hashOf(token),
    ]);
    const row = result.rows[0];
    if (row === undefined) {
      throw new Error('lookup_refresh_token : aucune ligne rendue');
    }
    return row;
  }

  async refresh(presentedToken: string, clientIp: string): Promise<RefreshResult> {
    if (!this.throttle.allow(clientIp, this.hashOf(presentedToken))) {
      return { outcome: 'THROTTLED' };
    }

    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const verdict = await this.lookup(client, presentedToken);

      switch (verdict.verdict) {
        case 'USABLE': {
          const issued = await this.rotate(client, verdict);
          await client.query('COMMIT');
          return issued;
        }
        case 'GRACE': {
          // La valeur en clair du successeur n'existe NULLE PART (token_hash
          // seul en base, §3.6) : la rendre est matériellement impossible.
          // Le cas réel : la réponse de rotation s'est perdue sur le réseau
          // RDC ; le client n'a que l'ancien jeton. Si on ne lui rendait
          // qu'un jeton d'accès, il repartirait avec son ancien jeton, la
          // grâce expirerait, et son PROCHAIN refresh serait classé REPLAY —
          // on tuerait la session d'une famille pour une réponse perdue.
          //
          // Donc : on TOURNE le successeur orphelin (jamais reçu, encore
          // ACTIVE) et on rend cette nouvelle valeur. Aucun jeton n'est
          // « fabriqué » en plus : à tout instant la session garde EXACTEMENT
          // un jeton ACTIVE (l'index unique partiel l'impose). Et la
          // détection de vol reste intacte : quiconque présenterait le
          // successeur hors grâce tomberait sur REPLAY.
          const successor = await this.readTokenStatus(client, verdict.successor_id);
          if (successor === 'ACTIVE' && verdict.successor_id !== null) {
            const rotated = await this.rotate(
              client,
              { ...verdict, token_id: verdict.successor_id },
            );
            await client.query('COMMIT');
            return rotated;
          }
          // Le successeur a déjà vécu (le client l'a bien reçu et tourné) :
          // ce rejeu-là est un doublon réseau bénin — jeton d'accès neuf sur
          // la session vivante, aucun nouveau jeton de rafraîchissement.
          const access = await this.provider.issueAccessToken({
            sub: verdict.account_id!,
            sid: verdict.session_id!,
          });
          await client.query('COMMIT');
          return {
            outcome: 'OK',
            accessToken: access.token,
            accessTokenExpiresAt: access.expiresAt,
          };
        }
        case 'REPLAY': {
          // Un jeton mort présenté sous une session vivante : le porteur
          // légitime et le voleur ne peuvent pas être départagés — on coupe
          // TOUTE la session, la base cascade sur les jetons (C1).
          await client.query(
            "UPDATE sessions SET status = 'REVOKED', revoke_reason = 'REPLAY_DETECTED' WHERE id = $1 AND status = 'ACTIVE'",
            [verdict.session_id],
          );
          await client.query('COMMIT');
          return { outcome: 'REPLAY_DETECTED' };
        }
        default: {
          // DEAD, UNKNOWN : refus sec, aucune information rendue.
          await client.query('COMMIT');
          return { outcome: 'REFUSED' };
        }
      }
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  // Lecture d'état SANS le hash (C10 : token_hash reste illisible ; status
  // l'est). Ce n'est pas un filtre de sécurité — la décision de sécurité est
  // déjà tranchée par le verdict de la base.
  private async readTokenStatus(
    client: PoolClient,
    tokenId: string | null,
  ): Promise<string | null> {
    if (tokenId === null) {
      return null;
    }
    const result = await client.query<{ status: string }>(
      'SELECT status FROM session_refresh_tokens WHERE id = $1',
      [tokenId],
    );
    return result.rows[0]?.status ?? null;
  }

  // Rotation ATOMIQUE (§3.13 : transaction locale, zéro appel réseau dedans) :
  // l'ancien passe ROTATED (libère le créneau ACTIVE unique) → le successeur
  // naît → le chaînage se pose. L'ordre est imposé par l'index unique partiel.
  private async rotate(client: PoolClient, verdict: Verdict): Promise<RefreshResult> {
    const successorToken = randomBytes(32).toString('base64url');

    await client.query(
      `UPDATE session_refresh_tokens
          SET status = 'ROTATED', grace_until = now() + make_interval(secs => $2)
        WHERE id = $1`,
      [verdict.token_id, this.config.graceWindowSeconds],
    );

    const inserted = await client.query<{ id: string }>(
      `INSERT INTO session_refresh_tokens (session_id, jti, token_hash, expires_at)
       SELECT $1, $2, $3,
              LEAST(now() + make_interval(secs => $4), s.absolute_expires_at)
         FROM sessions s WHERE s.id = $1
       RETURNING id`,
      [
        verdict.session_id,
        randomUUID(),
        this.hashOf(successorToken),
        this.config.refreshTokenTtlSeconds,
      ],
    );
    const successorId = inserted.rows[0]?.id;
    if (successorId === undefined) {
      throw new Error('rotation : le successeur n\'a pas été créé');
    }

    await client.query(
      'UPDATE session_refresh_tokens SET replaced_by_id = $2 WHERE id = $1',
      [verdict.token_id, successorId],
    );

    const access = await this.provider.issueAccessToken({
      sub: verdict.account_id!,
      sid: verdict.session_id!,
    });
    return {
      outcome: 'OK',
      accessToken: access.token,
      accessTokenExpiresAt: access.expiresAt,
      refreshToken: successorToken,
    };
  }

  /** logout : révocation serveur de LA session portée par le jeton d'accès. */
  async logout(accountId: string, sessionId: string): Promise<RevokeResult> {
    // BOLA : la clause account_id est le contrôle d'accès au niveau objet —
    // un compte ne coupe QUE ses sessions, même en présentant un sid étranger.
    const result = await this.pool.query(
      `UPDATE sessions SET status = 'REVOKED', revoke_reason = 'LOGOUT'
        WHERE id = $1 AND account_id = $2 AND status = 'ACTIVE'`,
      [sessionId, accountId],
    );
    if (result.rowCount === 0) {
      return { outcome: 'REFUSED' };
    }
    return { outcome: 'OK', revokedSessions: result.rowCount ?? 0 };
  }

  /** revoke-all : couper TOUTES les sessions du compte (vol de poste). */
  async revokeAll(accountId: string): Promise<RevokeResult> {
    const result = await this.pool.query(
      `UPDATE sessions SET status = 'REVOKED', revoke_reason = 'LOGOUT_ALL'
        WHERE account_id = $1 AND status = 'ACTIVE'`,
      [accountId],
    );
    return { outcome: 'OK', revokedSessions: result.rowCount ?? 0 };
  }
}
