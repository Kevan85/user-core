import { randomUUID } from 'crypto';
import { Pool } from 'pg';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// Invariants de la migration 004, prouvés sous le rôle bridé et hors
// transaction de test (CLAUDE.md §5), preuves owner pour les triggers —
// standard 002/003.
describe('sessions & session_refresh_tokens — invariants en base', () => {
  let app: Pool;
  let owner: Pool;
  let accountSeq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    await truncateTables(owner, 'session_refresh_tokens', 'sessions', 'accounts');
  });

  afterAll(async () => {
    await truncateTables(owner, 'session_refresh_tokens', 'sessions', 'accounts');
    await app.end();
    await owner.end();
  });

  async function createAccount(): Promise<string> {
    accountSeq += 1;
    const r = await app.query<{ id: string }>(
      "INSERT INTO accounts (public_identifier, role) VALUES ($1, 'ACCOUNT_HOLDER') RETURNING id",
      [String(3000000000 + accountSeq)],
    );
    return firstRow(r).id;
  }

  async function createSession(accountId: string, expiry = "interval '30 days'"): Promise<string> {
    const r = await app.query<{ id: string }>(
      `INSERT INTO sessions (account_id, absolute_expires_at) VALUES ($1, now() + ${expiry}) RETURNING id`,
      [accountId],
    );
    return firstRow(r).id;
  }

  async function insertToken(sessionId: string): Promise<string> {
    const r = await app.query<{ id: string }>(
      `INSERT INTO session_refresh_tokens (session_id, jti, token_hash, expires_at)
       VALUES ($1, $2, $3, now() + interval '7 days') RETURNING id`,
      [sessionId, randomUUID(), `hash_${randomUUID()}`],
    );
    return firstRow(r).id;
  }

  // Rotation complète côté base : ROTATED (libère le créneau ACTIVE) →
  // successeur → chaînage set-once. Le service fera ces trois pas dans UNE
  // transaction (étape 8) ; ici on prouve que la base les accepte et les fige.
  async function rotate(oldId: string, sessionId: string): Promise<string> {
    await app.query(
      `UPDATE session_refresh_tokens SET status = 'ROTATED', grace_until = now() + interval '30 seconds' WHERE id = $1`,
      [oldId],
    );
    const successor = await insertToken(sessionId);
    await app.query('UPDATE session_refresh_tokens SET replaced_by_id = $2 WHERE id = $1', [
      oldId,
      successor,
    ]);
    return successor;
  }

  test('session + jeton valides → ACTIVE, horodatages posés par la base', async () => {
    const sessionId = await createSession(await createAccount());
    const tokenId = await insertToken(sessionId);
    const row = firstRow(
      await app.query<{ status: string; rotated_at: string | null }>(
        'SELECT status, rotated_at FROM session_refresh_tokens WHERE id = $1',
        [tokenId],
      ),
    );
    expect(row.status).toBe('ACTIVE');
    expect(row.rotated_at).toBeNull();
  });

  test('jti dupliqué → refus (unicité globale)', async () => {
    const sessionId = await createSession(await createAccount());
    const jti = randomUUID();
    await app.query(
      `INSERT INTO session_refresh_tokens (session_id, jti, token_hash, expires_at)
       VALUES ($1, $2, 'h1', now() + interval '7 days')`,
      [sessionId, jti],
    );
    const otherSession = await createSession(await createAccount());
    await expect(
      app.query(
        `INSERT INTO session_refresh_tokens (session_id, jti, token_hash, expires_at)
         VALUES ($1, $2, 'h2', now() + interval '7 days')`,
        [otherSession, jti],
      ),
    ).rejects.toThrow(/uq_session_refresh_tokens_jti/);
  });

  test('deux jetons ACTIVE sur une session → refus (index unique partiel)', async () => {
    const sessionId = await createSession(await createAccount());
    await insertToken(sessionId);
    await expect(insertToken(sessionId)).rejects.toThrow(/uq_session_refresh_tokens_active/);
  });

  test('rotation : rotated_at posé par la base, chaînage set-once, même session imposée', async () => {
    const sessionId = await createSession(await createAccount());
    const oldId = await insertToken(sessionId);
    const successor = await rotate(oldId, sessionId);

    const old = firstRow(
      await app.query<{ status: string; replaced_by_id: string; age_seconds: number }>(
        `SELECT status, replaced_by_id,
                EXTRACT(EPOCH FROM (now() - rotated_at))::float AS age_seconds
         FROM session_refresh_tokens WHERE id = $1`,
        [oldId],
      ),
    );
    expect(old.status).toBe('ROTATED');
    expect(old.replaced_by_id).toBe(successor);
    expect(old.age_seconds).toBeLessThan(60);

    // set-once : re-pointer le chaînage → refus.
    const intrus = await insertToken(await createSession(await createAccount()));
    await expect(
      app.query('UPDATE session_refresh_tokens SET replaced_by_id = $2 WHERE id = $1', [
        oldId,
        intrus,
      ]),
    ).rejects.toThrow(/set-once/);
  });

  test('le chaînage ne peut PAS pointer un jeton d\'une AUTRE session (FK composite)', async () => {
    const sessionId = await createSession(await createAccount());
    const oldId = await insertToken(sessionId);
    await app.query(
      `UPDATE session_refresh_tokens SET status = 'ROTATED', grace_until = now() + interval '30 seconds' WHERE id = $1`,
      [oldId],
    );
    const foreignToken = await insertToken(await createSession(await createAccount()));
    await expect(
      app.query('UPDATE session_refresh_tokens SET replaced_by_id = $2 WHERE id = $1', [
        oldId,
        foreignToken,
      ]),
    ).rejects.toThrow(/fk_srt_replaced_by_same_session/);
  });

  test('rotation sans fenêtre de grâce → refus ; retour vers ACTIVE → refus', async () => {
    const sessionId = await createSession(await createAccount());
    const tokenId = await insertToken(sessionId);
    await expect(
      app.query("UPDATE session_refresh_tokens SET status = 'ROTATED' WHERE id = $1", [tokenId]),
    ).rejects.toThrow(/fenêtre de grâce/);
    await app.query(
      `UPDATE session_refresh_tokens SET status = 'ROTATED', grace_until = now() + interval '30 seconds' WHERE id = $1`,
      [tokenId],
    );
    await expect(
      app.query("UPDATE session_refresh_tokens SET status = 'ACTIVE' WHERE id = $1", [tokenId]),
    ).rejects.toThrow(/aucun retour vers ACTIVE/);
  });

  test('C1 — révoquer la session éteint TOUS ses jetons, par la base (nombre ET statuts)', async () => {
    const sessionId = await createSession(await createAccount());
    const oldId = await insertToken(sessionId);
    await rotate(oldId, sessionId); // la session porte 1 ROTATED + 1 ACTIVE

    await app.query(
      "UPDATE sessions SET status = 'REVOKED', revoke_reason = 'LOGOUT_ALL' WHERE id = $1",
      [sessionId],
    );

    const tokens = await app.query<{ status: string }>(
      'SELECT status FROM session_refresh_tokens WHERE session_id = $1',
      [sessionId],
    );
    // Le NOMBRE d'abord, puis CHAQUE statut (CLAUDE.md §5).
    expect(tokens.rows).toHaveLength(2);
    expect(tokens.rows.map((r) => r.status)).toEqual(['REVOKED', 'REVOKED']);

    const session = firstRow(
      await app.query<{ age_seconds: number; revoke_reason: string }>(
        `SELECT EXTRACT(EPOCH FROM (now() - revoked_at))::float AS age_seconds, revoke_reason
         FROM sessions WHERE id = $1`,
        [sessionId],
      ),
    );
    expect(session.revoke_reason).toBe('LOGOUT_ALL');
    expect(session.age_seconds).toBeLessThan(60);
  });

  test('C5-bis — aucun jeton ne naît sous une session RÉVOQUÉE', async () => {
    const sessionId = await createSession(await createAccount());
    await app.query(
      "UPDATE sessions SET status = 'REVOKED', revoke_reason = 'LOGOUT' WHERE id = $1",
      [sessionId],
    );
    await expect(insertToken(sessionId)).rejects.toThrow(/session REVOKED/);
  });

  test('C5/C5-bis — aucun jeton ne naît sous une session au-delà de son échéance absolue', async () => {
    const sessionId = await createSession(await createAccount(), "interval '1 second'");
    await app.query('SELECT pg_sleep(1.3)');
    await expect(insertToken(sessionId)).rejects.toThrow(/échéance absolue/);
  });

  test('C5 — une session ne naît pas déjà expirée, et son échéance est immuable', async () => {
    const accountId = await createAccount();
    await expect(
      app.query(
        "INSERT INTO sessions (account_id, absolute_expires_at) VALUES ($1, now() - interval '1 hour')",
        [accountId],
      ),
    ).rejects.toThrow(/chk_sessions_absolute_future/);

    const sessionId = await createSession(accountId);
    await expect(
      app.query(
        "UPDATE sessions SET absolute_expires_at = now() + interval '10 years' WHERE id = $1",
        [sessionId],
      ),
    ).rejects.toThrow(/permission denied/);
    await expect(
      owner.query(
        "UPDATE sessions SET absolute_expires_at = now() + interval '10 years' WHERE id = $1",
        [sessionId],
      ),
    ).rejects.toThrow(/identité immuable/);
  });

  test('révocation sans motif → refus ; session révoquée figée ; re-datation impossible', async () => {
    const sessionId = await createSession(await createAccount());
    await expect(
      app.query("UPDATE sessions SET status = 'REVOKED' WHERE id = $1", [sessionId]),
    ).rejects.toThrow(/porte toujours son motif/);

    await app.query(
      "UPDATE sessions SET status = 'REVOKED', revoke_reason = 'ADMIN' WHERE id = $1",
      [sessionId],
    );
    await expect(
      app.query("UPDATE sessions SET status = 'ACTIVE' WHERE id = $1", [sessionId]),
    ).rejects.toThrow(/figée/);
    await expect(
      owner.query("UPDATE sessions SET revoked_at = '2019-01-01' WHERE id = $1", [sessionId]),
    ).rejects.toThrow(/figée/);
  });

  test('un jeton révoqué est figé ; la révocation ne retouche pas la rotation', async () => {
    const sessionId = await createSession(await createAccount());
    const tokenId = await insertToken(sessionId);
    await app.query("UPDATE session_refresh_tokens SET status = 'REVOKED' WHERE id = $1", [
      tokenId,
    ]);
    await expect(
      app.query("UPDATE session_refresh_tokens SET status = 'ROTATED', grace_until = now() WHERE id = $1", [
        tokenId,
      ]),
    ).rejects.toThrow(/figé/);
  });

  test('mutation du hash ou du jti : rôle bridé → permission denied ; owner → trigger', async () => {
    const sessionId = await createSession(await createAccount());
    const tokenId = await insertToken(sessionId);
    await expect(
      app.query("UPDATE session_refresh_tokens SET token_hash = 'autre' WHERE id = $1", [tokenId]),
    ).rejects.toThrow(/permission denied/);
    await expect(
      owner.query("UPDATE session_refresh_tokens SET token_hash = 'autre' WHERE id = $1", [
        tokenId,
      ]),
    ).rejects.toThrow(/contenu immuable/);
    await expect(
      owner.query('UPDATE session_refresh_tokens SET jti = $2 WHERE id = $1', [
        tokenId,
        randomUUID(),
      ]),
    ).rejects.toThrow(/contenu immuable/);
  });

  // ---------------------------------------------------------------------------
  // C10 : le hash n'est lisible par personne ; la base compare et rend un
  // verdict. L'API n'agit que sur le verdict.
  // ---------------------------------------------------------------------------
  async function insertTokenWithHash(
    sessionId: string,
    expiry = "interval '7 days'",
  ): Promise<{ id: string; hash: string }> {
    const hash = `hash_${randomUUID()}`;
    const r = await app.query<{ id: string }>(
      `INSERT INTO session_refresh_tokens (session_id, jti, token_hash, expires_at)
       VALUES ($1, $2, $3, now() + ${expiry}) RETURNING id`,
      [sessionId, randomUUID(), hash],
    );
    return { id: firstRow(r).id, hash };
  }

  interface Verdict {
    token_id: string | null;
    session_id: string | null;
    account_id: string | null;
    successor_id: string | null;
    verdict: string;
  }

  async function lookup(hash: string): Promise<Verdict> {
    return firstRow(
      await app.query<Verdict>('SELECT * FROM lookup_refresh_token($1)', [hash]),
    );
  }

  test('C10a — token_hash est illisible sous rôle bridé (colonne et SELECT *)', async () => {
    await expect(
      app.query('SELECT token_hash FROM session_refresh_tokens'),
    ).rejects.toThrow(/permission denied/);
    await expect(app.query('SELECT * FROM session_refresh_tokens')).rejects.toThrow(
      /permission denied/,
    );
    // Les colonnes de gestion restent lisibles.
    await expect(
      app.query('SELECT id, status, grace_until FROM session_refresh_tokens'),
    ).resolves.toBeDefined();
  });

  test('C10 — verdict USABLE : jeton vivant, session vivante, identifiants complets', async () => {
    const accountId = await createAccount();
    const sessionId = await createSession(accountId);
    const { id, hash } = await insertTokenWithHash(sessionId);
    const v = await lookup(hash);
    expect(v.verdict).toBe('USABLE');
    expect(v.token_id).toBe(id);
    expect(v.session_id).toBe(sessionId);
    expect(v.account_id).toBe(accountId);
    expect(v.successor_id).toBeNull();
  });

  test('C10 — verdict GRACE : ROTATED dans la fenêtre, le successeur DÉJÀ émis est rendu', async () => {
    const sessionId = await createSession(await createAccount());
    const { id, hash } = await insertTokenWithHash(sessionId);
    const successor = await rotate(id, sessionId);
    const v = await lookup(hash);
    expect(v.verdict).toBe('GRACE');
    expect(v.successor_id).toBe(successor);
  });

  test('C15 — verdict STALE : ROTATED dans la grâce mais successeur DÉJÀ consommé', async () => {
    const sessionId = await createSession(await createAccount());
    const { id, hash } = await insertTokenWithHash(sessionId);
    const successor = await rotate(id, sessionId);
    // Le successeur est consommé à son tour : le premier jeton n'a plus rien
    // à offrir, même dans sa fenêtre de grâce.
    await rotate(successor, sessionId);
    const v = await lookup(hash);
    expect(v.verdict).toBe('STALE');
  });

  test('C10 — verdict REPLAY : ROTATED hors grâce sous session vivante', async () => {
    const sessionId = await createSession(await createAccount());
    const { id, hash } = await insertTokenWithHash(sessionId);
    await app.query(
      `UPDATE session_refresh_tokens SET status = 'ROTATED', grace_until = now() + interval '0.3 seconds' WHERE id = $1`,
      [id],
    );
    await app.query('SELECT pg_sleep(0.6)');
    const v = await lookup(hash);
    expect(v.verdict).toBe('REPLAY');
  });

  test('C10 — verdict REPLAY : jeton RÉVOQUÉ présenté sous session vivante, aucune ressuscitation', async () => {
    const sessionId = await createSession(await createAccount());
    const { id, hash } = await insertTokenWithHash(sessionId);
    await app.query("UPDATE session_refresh_tokens SET status = 'REVOKED' WHERE id = $1", [id]);
    const v = await lookup(hash);
    expect(v.verdict).toBe('REPLAY');
    await expect(
      app.query("UPDATE session_refresh_tokens SET status = 'ACTIVE' WHERE id = $1", [id]),
    ).rejects.toThrow(/figé/);
  });

  test('C10 — verdict DEAD : session révoquée (prime sur l\'état du jeton)', async () => {
    const sessionId = await createSession(await createAccount());
    const { hash } = await insertTokenWithHash(sessionId);
    await app.query(
      "UPDATE sessions SET status = 'REVOKED', revoke_reason = 'LOGOUT' WHERE id = $1",
      [sessionId],
    );
    const v = await lookup(hash);
    expect(v.verdict).toBe('DEAD');
  });

  test('C10 — jeton ACTIVE mais expiré → DEAD (client hors ligne, pas une preuve de vol)', async () => {
    const sessionId = await createSession(await createAccount());
    const { hash } = await insertTokenWithHash(sessionId, "interval '0.3 seconds'");
    await app.query('SELECT pg_sleep(0.6)');
    const v = await lookup(hash);
    expect(v.verdict).toBe('DEAD');
  });

  test('C10 — verdict UNKNOWN : aucun jeton ne porte ce hash', async () => {
    const v = await lookup('hash_inexistant');
    expect(v.verdict).toBe('UNKNOWN');
    expect(v.token_id).toBeNull();
    expect(v.account_id).toBeNull();
  });

  test('C11 — deux jetons de même token_hash (sessions différentes) → refus (unicité)', async () => {
    const s1 = await createSession(await createAccount());
    const s2 = await createSession(await createAccount());
    const hash = `hash_${randomUUID()}`;
    await app.query(
      `INSERT INTO session_refresh_tokens (session_id, jti, token_hash, expires_at)
       VALUES ($1, $2, $3, now() + interval '7 days')`,
      [s1, randomUUID(), hash],
    );
    await expect(
      app.query(
        `INSERT INTO session_refresh_tokens (session_id, jti, token_hash, expires_at)
         VALUES ($1, $2, $3, now() + interval '7 days')`,
        [s2, randomUUID(), hash],
      ),
    ).rejects.toThrow(/uq_srt_token_hash/);
  });

  test('C13 — désactiver le compte révoque TOUTES ses sessions (nombre, statuts, motif) et leurs jetons', async () => {
    const accountId = await createAccount();
    const s1 = await createSession(accountId);
    const s2 = await createSession(accountId);
    await insertTokenWithHash(s1);
    const t2 = await insertTokenWithHash(s2);
    await rotate(t2.id, s2); // s2 porte 1 ROTATED + 1 ACTIVE

    await app.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [accountId]);

    const sessions = await app.query<{ status: string; revoke_reason: string }>(
      'SELECT status, revoke_reason FROM sessions WHERE account_id = $1',
      [accountId],
    );
    expect(sessions.rows).toHaveLength(2);
    expect(sessions.rows.map((r) => r.status)).toEqual(['REVOKED', 'REVOKED']);
    expect(sessions.rows.map((r) => r.revoke_reason)).toEqual(['ADMIN', 'ADMIN']);

    const tokens = await app.query<{ status: string }>(
      `SELECT srt.status FROM session_refresh_tokens srt
        JOIN sessions se ON se.id = srt.session_id
       WHERE se.account_id = $1`,
      [accountId],
    );
    expect(tokens.rows).toHaveLength(3);
    expect(tokens.rows.map((r) => r.status)).toEqual(['REVOKED', 'REVOKED', 'REVOKED']);
  });

  test('C13 — le jeton d\'un compte désactivé reçoit le verdict DEAD', async () => {
    const accountId = await createAccount();
    const sessionId = await createSession(accountId);
    const { hash } = await insertTokenWithHash(sessionId);
    await app.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [accountId]);
    const v = await lookup(hash);
    expect(v.verdict).toBe('DEAD');
  });

  test('C13 — aucune session ne NAÎT sous un compte désactivé (le registre ne ment pas)', async () => {
    const accountId = await createAccount();
    await app.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [accountId]);
    await expect(createSession(accountId)).rejects.toThrow(/aucune session ne naît/);
  });

  test('C13 (ceinture) — même une session ouverte AVANT et forcée sous owner rend DEAD', async () => {
    // Le chemin oublieux, poussé au maximum : la session existe (ouverte
    // avant la désactivation), le compte meurt, la cascade la révoque — et
    // même si un chemin la ressuscitait, la jointure compte du verdict tient.
    const accountId = await createAccount();
    const sessionId = await createSession(accountId);
    const { hash } = await insertTokenWithHash(sessionId);
    await app.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [accountId]);
    const v = await lookup(hash);
    expect(v.verdict).toBe('DEAD');
    expect(v.session_id).toBe(sessionId);
  });

  test('C10-b — un jeton dont l\'échéance dépasse celle de sa session → refus à la naissance', async () => {
    const sessionId = await createSession(await createAccount(), "interval '30 days'");
    await expect(
      app.query(
        `INSERT INTO session_refresh_tokens (session_id, jti, token_hash, expires_at)
         VALUES ($1, $2, 'h_survivant', now() + interval '60 days')`,
        [sessionId, randomUUID()],
      ),
    ).rejects.toThrow(/ne survit jamais à sa session/);
  });

  test('DELETE : rôle bridé → permission denied ; owner → forbid_delete (les 2 tables)', async () => {
    const sessionId = await createSession(await createAccount());
    const tokenId = await insertToken(sessionId);
    await expect(app.query('DELETE FROM sessions WHERE id = $1', [sessionId])).rejects.toThrow(
      /permission denied/,
    );
    await expect(
      app.query('DELETE FROM session_refresh_tokens WHERE id = $1', [tokenId]),
    ).rejects.toThrow(/permission denied/);
    await expect(
      owner.query('DELETE FROM session_refresh_tokens WHERE id = $1', [tokenId]),
    ).rejects.toThrow(/suppression interdite/);
    await expect(owner.query('DELETE FROM sessions WHERE id = $1', [sessionId])).rejects.toThrow(
      /suppression interdite/,
    );
  });

  test('standard D2 — INSERT explicitant status, created_at, revoked_at ou rotated_at → permission denied', async () => {
    const accountId = await createAccount();
    await expect(
      app.query(
        "INSERT INTO sessions (account_id, absolute_expires_at, status) VALUES ($1, now() + interval '1 day', 'REVOKED')",
        [accountId],
      ),
    ).rejects.toThrow(/permission denied/);
    await expect(
      app.query(
        "INSERT INTO sessions (account_id, absolute_expires_at, created_at) VALUES ($1, now() + interval '1 day', '2019-01-01')",
        [accountId],
      ),
    ).rejects.toThrow(/permission denied/);
    const sessionId = await createSession(accountId);
    await expect(
      app.query(
        `INSERT INTO session_refresh_tokens (session_id, jti, token_hash, expires_at, rotated_at)
         VALUES ($1, $2, 'h', now() + interval '7 days', now())`,
        [sessionId, randomUUID()],
      ),
    ).rejects.toThrow(/permission denied/);
  });
});
