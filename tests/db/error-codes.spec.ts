import { randomUUID } from 'crypto';
import { Pool } from 'pg';
import { DB_ERROR, dbErrorCode } from '../../src/db/errors';
import { createAccount as createAccountFixture } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// Chaque famille de garde lève SON code (migration 005). Les tests assertent
// le CODE, jamais le message : c'est précisément le point — un message se
// reformule sans rien casser, un code est le contrat.
const HASH = '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$ZmF1eGhhc2hkZXRlc3Q';

async function codeOf(run: () => Promise<unknown>): Promise<string | undefined> {
  try {
    await run();
  } catch (err) {
    return dbErrorCode(err);
  }
  throw new Error('une violation était attendue : la garde n\'a pas levé');
}

describe('Codes d\'erreur des gardes (005)', () => {
  let app: Pool;
  let owner: Pool;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    await truncateTables(owner, 'session_refresh_tokens', 'sessions', 'account_secrets', 'accounts');
  });

  afterAll(async () => {
    await truncateTables(owner, 'session_refresh_tokens', 'sessions', 'account_secrets', 'accounts');
    await app.end();
    await owner.end();
  });

  async function newAccount(): Promise<string> {
    seq += 1;
    // Chemin unique (011) ; le secret de naissance est retiré car cette suite
    // pose les SIENS (au plus un ACTIVE par compte, 003).
    return createAccountFixture(app, String(6000000000 + seq), { retireInitialSecret: true });
  }

  test('P0101 — identité/contenu immuable', async () => {
    const id = await newAccount();
    await expect(
      codeOf(() =>
        owner.query("UPDATE accounts SET public_identifier = '1111111111' WHERE id = $1", [id]),
      ),
    ).resolves.toBe(DB_ERROR.IMMUTABLE);
  });

  test('P0102 — transition interdite', async () => {
    const id = await newAccount();
    await app.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [id]);
    // La ligne est désormais figée : c'est P0103 qui doit sortir en premier
    // pour un compte. On prouve P0102 sur une session sans motif.
    const other = await newAccount();
    const sessionId = firstRow(
      await app.query<{ id: string }>(
        "INSERT INTO sessions (account_id, absolute_expires_at) VALUES ($1, now() + interval '1 day') RETURNING id",
        [other],
      ),
    ).id;
    await expect(
      codeOf(() => app.query("UPDATE sessions SET status = 'REVOKED' WHERE id = $1", [sessionId])),
    ).resolves.toBe(DB_ERROR.FORBIDDEN_TRANSITION);
  });

  test('P0103 — ligne terminale figée', async () => {
    const accountId = await newAccount();
    const secretId = firstRow(
      await app.query<{ id: string }>(
        'INSERT INTO account_secrets (account_id, secret_hash) VALUES ($1, $2) RETURNING id',
        [accountId, HASH],
      ),
    ).id;
    await app.query("UPDATE account_secrets SET status = 'RETIRED' WHERE id = $1", [secretId]);
    await expect(
      codeOf(() =>
        app.query("UPDATE account_secrets SET status = 'ACTIVE' WHERE id = $1", [secretId]),
      ),
    ).resolves.toBe(DB_ERROR.FROZEN_ROW);
  });

  test('P0104 — horodatage de registre réécrit', async () => {
    const accountId = await newAccount();
    const secretId = firstRow(
      await app.query<{ id: string }>(
        'INSERT INTO account_secrets (account_id, secret_hash) VALUES ($1, $2) RETURNING id',
        [accountId, HASH],
      ),
    ).id;
    await expect(
      codeOf(() =>
        owner.query("UPDATE account_secrets SET retired_at = '2019-01-01' WHERE id = $1", [
          secretId,
        ]),
      ),
    ).resolves.toBe(DB_ERROR.REGISTRY_TIMESTAMP);
  });

  test('P0105 — un verrou dans le futur ne recule jamais', async () => {
    const accountId = await newAccount();
    const secretId = firstRow(
      await app.query<{ id: string }>(
        'INSERT INTO account_secrets (account_id, secret_hash) VALUES ($1, $2) RETURNING id',
        [accountId, HASH],
      ),
    ).id;
    await app.query(
      "UPDATE account_secrets SET locked_until = now() + interval '15 minutes' WHERE id = $1",
      [secretId],
    );
    await expect(
      codeOf(() =>
        app.query('UPDATE account_secrets SET locked_until = NULL WHERE id = $1', [secretId]),
      ),
    ).resolves.toBe(DB_ERROR.LOCK_WOULD_RECEDE);
  });

  test('P0106 — compteur d\'échecs illégal', async () => {
    const accountId = await newAccount();
    const secretId = firstRow(
      await app.query<{ id: string }>(
        'INSERT INTO account_secrets (account_id, secret_hash) VALUES ($1, $2) RETURNING id',
        [accountId, HASH],
      ),
    ).id;
    await expect(
      codeOf(() =>
        app.query('UPDATE account_secrets SET failed_attempts = 7 WHERE id = $1', [secretId]),
      ),
    ).resolves.toBe(DB_ERROR.ILLEGAL_ATTEMPT_COUNTER);
  });

  test('P0107 — suppression interdite', async () => {
    const id = await newAccount();
    await expect(
      codeOf(() => owner.query('DELETE FROM accounts WHERE id = $1', [id])),
    ).resolves.toBe(DB_ERROR.DELETE_FORBIDDEN);
  });

  test('P0108 — naissance sous un parent mort', async () => {
    const accountId = await newAccount();
    await app.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [accountId]);
    await expect(
      codeOf(() =>
        app.query(
          "INSERT INTO sessions (account_id, absolute_expires_at) VALUES ($1, now() + interval '1 day')",
          [accountId],
        ),
      ),
    ).resolves.toBe(DB_ERROR.DEAD_PARENT);

    // Et côté jetons : sous une session révoquée.
    const live = await newAccount();
    const sessionId = firstRow(
      await app.query<{ id: string }>(
        "INSERT INTO sessions (account_id, absolute_expires_at) VALUES ($1, now() + interval '1 day') RETURNING id",
        [live],
      ),
    ).id;
    await app.query(
      "UPDATE sessions SET status = 'REVOKED', revoke_reason = 'LOGOUT' WHERE id = $1",
      [sessionId],
    );
    await expect(
      codeOf(() =>
        app.query(
          `INSERT INTO session_refresh_tokens (session_id, jti, token_hash, expires_at)
           VALUES ($1, $2, 'h', now() + interval '1 hour')`,
          [sessionId, randomUUID()],
        ),
      ),
    ).resolves.toBe(DB_ERROR.DEAD_PARENT);
  });
});
