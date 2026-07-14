import { Pool } from 'pg';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// Invariants de la migration 003, prouvés sous le rôle bridé et hors
// transaction de test (CLAUDE.md §5), avec les preuves « sous owner » pour
// les triggers — le standard posé en 002.
const HASH = '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$ZmF1eGhhc2hkZXRlc3Q';
const HASH2 = '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$YXV0cmVmYXV4aGFzaA';

describe('account_secrets — invariants en base', () => {
  let app: Pool;
  let owner: Pool;
  let accountSeq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    await truncateTables(owner, 'account_secrets', 'accounts');
  });

  afterAll(async () => {
    await truncateTables(owner, 'account_secrets', 'accounts');
    await app.end();
    await owner.end();
  });

  async function createAccount(): Promise<string> {
    accountSeq += 1;
    const identifier = String(2000000000 + accountSeq);
    const r = await app.query<{ id: string }>(
      "INSERT INTO accounts (public_identifier, role) VALUES ($1, 'ACCOUNT_HOLDER') RETURNING id",
      [identifier],
    );
    return firstRow(r).id;
  }

  async function insertSecret(accountId: string, hash = HASH): Promise<string> {
    const r = await app.query<{ id: string }>(
      'INSERT INTO account_secrets (account_id, secret_hash) VALUES ($1, $2) RETURNING id',
      [accountId, hash],
    );
    return firstRow(r).id;
  }

  test('INSERT valide → ACTIVE, compteur à 0, non verrouillé (défauts de la base)', async () => {
    const id = await insertSecret(await createAccount());
    const row = firstRow(
      await app.query<{ status: string; failed_attempts: number; locked_until: string | null }>(
        'SELECT status, failed_attempts, locked_until FROM account_secrets WHERE id = $1',
        [id],
      ),
    );
    expect(row.status).toBe('ACTIVE');
    expect(row.failed_attempts).toBe(0);
    expect(row.locked_until).toBeNull();
  });

  test('C7 — un hash non argon2id (clair, bcrypt…) est NON REPRÉSENTABLE', async () => {
    const accountId = await createAccount();
    await expect(insertSecret(accountId, 'motdepasseenclair')).rejects.toThrow(
      /chk_account_secrets_argon2id/,
    );
    await expect(insertSecret(accountId, '$2b$10$abcdefghijklmnopqrstuv')).rejects.toThrow(
      /chk_account_secrets_argon2id/,
    );
  });

  test('deux secrets ACTIVE pour un compte → refus (index unique partiel)', async () => {
    const accountId = await createAccount();
    await insertSecret(accountId);
    await expect(insertSecret(accountId, HASH2)).rejects.toThrow(/uq_account_secrets_active/);
  });

  test('retrait puis nouveau secret → accepté ; retired_at posé par la BASE', async () => {
    const accountId = await createAccount();
    const oldId = await insertSecret(accountId);
    await app.query("UPDATE account_secrets SET status = 'RETIRED' WHERE id = $1", [oldId]);
    const row = firstRow(
      await app.query<{ age_seconds: number }>(
        `SELECT EXTRACT(EPOCH FROM (now() - retired_at))::float AS age_seconds
         FROM account_secrets WHERE id = $1`,
        [oldId],
      ),
    );
    expect(row.age_seconds).toBeLessThan(60);
    await expect(insertSecret(accountId, HASH2)).resolves.toBeDefined();
  });

  test('provisoire sans échéance / permanent avec échéance → refus CHECK', async () => {
    const accountId = await createAccount();
    await expect(
      app.query(
        'INSERT INTO account_secrets (account_id, secret_hash, is_temporary) VALUES ($1, $2, true)',
        [accountId, HASH],
      ),
    ).rejects.toThrow(/chk_account_secrets_temporary_pair/);
    await expect(
      app.query(
        "INSERT INTO account_secrets (account_id, secret_hash, expires_at) VALUES ($1, $2, now() + interval '1 day')",
        [accountId, HASH],
      ),
    ).rejects.toThrow(/chk_account_secrets_temporary_pair/);
  });

  test('résurrection RETIRED → ACTIVE → refus trigger (ligne figée)', async () => {
    const accountId = await createAccount();
    const id = await insertSecret(accountId);
    await app.query("UPDATE account_secrets SET status = 'RETIRED' WHERE id = $1", [id]);
    await expect(
      app.query("UPDATE account_secrets SET status = 'ACTIVE' WHERE id = $1", [id]),
    ).rejects.toThrow(/figée/);
  });

  test('mutation du hash : rôle bridé → permission denied ; owner → trigger (immuable)', async () => {
    const id = await insertSecret(await createAccount());
    await expect(
      app.query('UPDATE account_secrets SET secret_hash = $2 WHERE id = $1', [id, HASH2]),
    ).rejects.toThrow(/permission denied/);
    await expect(
      owner.query('UPDATE account_secrets SET secret_hash = $2 WHERE id = $1', [id, HASH2]),
    ).rejects.toThrow(/contenu immuable/);
  });

  test('re-datation de retired_at : rôle bridé → permission denied ; owner sur ligne ACTIVE → trigger', async () => {
    const id = await insertSecret(await createAccount());
    await expect(
      app.query("UPDATE account_secrets SET retired_at = '2019-01-01' WHERE id = $1", [id]),
    ).rejects.toThrow(/permission denied/);
    await expect(
      owner.query("UPDATE account_secrets SET retired_at = '2019-01-01' WHERE id = $1", [id]),
    ).rejects.toThrow(/posé par la base/);
  });

  test('C8 — un verrou dans le futur ne recule JAMAIS (ni passé, ni NULL) ; il peut s\'étendre', async () => {
    const id = await insertSecret(await createAccount());
    await app.query(
      "UPDATE account_secrets SET locked_until = now() + interval '15 minutes' WHERE id = $1",
      [id],
    );
    // « je verrouille, puis j'écris locked_until = hier » → refus.
    await expect(
      app.query(
        "UPDATE account_secrets SET locked_until = now() - interval '1 day' WHERE id = $1",
        [id],
      ),
    ).rejects.toThrow(/ne recule jamais/);
    await expect(
      app.query('UPDATE account_secrets SET locked_until = NULL WHERE id = $1', [id]),
    ).rejects.toThrow(/ne recule jamais/);
    // Extension stricte : autorisée (backoff progressif).
    await expect(
      app.query(
        "UPDATE account_secrets SET locked_until = now() + interval '30 minutes' WHERE id = $1",
        [id],
      ),
    ).resolves.toBeDefined();
    // Sous owner aussi : le verrou ne se contourne pas par privilège.
    await expect(
      owner.query("UPDATE account_secrets SET locked_until = '2019-01-01' WHERE id = $1", [id]),
    ).rejects.toThrow(/ne recule jamais/);
  });

  test('C8 — un verrou EXPIRÉ se remplace librement (déverrouillage par écoulement, pas par recul)', async () => {
    const id = await insertSecret(await createAccount());
    // Verrou déjà expiré, posé sous owner (le trigger n'interdit que le recul
    // d'un verrou encore actif).
    await owner.query(
      "UPDATE account_secrets SET locked_until = now() - interval '1 hour' WHERE id = $1",
      [id],
    );
    await expect(
      app.query(
        "UPDATE account_secrets SET locked_until = now() + interval '5 minutes' WHERE id = $1",
        [id],
      ),
    ).resolves.toBeDefined();
  });

  test('C8 — failed_attempts : +1 ou retour à 0, jamais un saut ni une décrue partielle', async () => {
    const id = await insertSecret(await createAccount());
    await app.query(
      'UPDATE account_secrets SET failed_attempts = failed_attempts + 1 WHERE id = $1',
      [id],
    );
    await app.query(
      'UPDATE account_secrets SET failed_attempts = failed_attempts + 1 WHERE id = $1',
      [id],
    );
    // Saut vers le haut → refus.
    await expect(
      app.query('UPDATE account_secrets SET failed_attempts = 7 WHERE id = $1', [id]),
    ).rejects.toThrow(/s'incrémente de 1 ou retombe à 0/);
    // Décrue partielle → refus (2 -> 1).
    await expect(
      app.query('UPDATE account_secrets SET failed_attempts = 1 WHERE id = $1', [id]),
    ).rejects.toThrow(/s'incrémente de 1 ou retombe à 0/);
    // Authentification réussie → retour à 0, autorisé.
    await app.query('UPDATE account_secrets SET failed_attempts = 0 WHERE id = $1', [id]);
    const row = firstRow(
      await app.query<{ failed_attempts: number }>(
        'SELECT failed_attempts FROM account_secrets WHERE id = $1',
        [id],
      ),
    );
    expect(row.failed_attempts).toBe(0);
  });

  test('DELETE : rôle bridé → permission denied ; owner → forbid_delete tient', async () => {
    const id = await insertSecret(await createAccount());
    await expect(
      app.query('DELETE FROM account_secrets WHERE id = $1', [id]),
    ).rejects.toThrow(/permission denied/);
    await expect(
      owner.query('DELETE FROM account_secrets WHERE id = $1', [id]),
    ).rejects.toThrow(/suppression interdite/);
    await expect(app.query('TRUNCATE account_secrets')).rejects.toThrow(/permission denied/);
  });

  test('C9a — lire secret_hash dans la TABLE sous rôle bridé → permission denied', async () => {
    await expect(app.query('SELECT secret_hash FROM account_secrets')).rejects.toThrow(
      /permission denied/,
    );
    // SELECT * embarque la colonne interdite : refusé aussi.
    await expect(app.query('SELECT * FROM account_secrets')).rejects.toThrow(
      /permission denied/,
    );
  });

  test('C9b/c — la vue authenticable_secrets ne montre que le vivant (nombre ET contenu)', async () => {
    // Quatre comptes : sain, retiré, provisoire expiré, verrouillé.
    const sain = await createAccount();
    await insertSecret(sain);

    const retire = await createAccount();
    const sRetire = await insertSecret(retire);
    await app.query("UPDATE account_secrets SET status = 'RETIRED' WHERE id = $1", [sRetire]);

    const expire = await createAccount();
    await app.query(
      "INSERT INTO account_secrets (account_id, secret_hash, is_temporary, expires_at) VALUES ($1, $2, true, now() - interval '1 hour')",
      [expire, HASH2],
    );

    const verrouille = await createAccount();
    const sVerrouille = await insertSecret(verrouille);
    await app.query(
      "UPDATE account_secrets SET locked_until = now() + interval '15 minutes' WHERE id = $1",
      [sVerrouille],
    );

    const rows = await app.query<{ account_id: string; secret_hash: string }>(
      'SELECT account_id, secret_hash FROM authenticable_secrets WHERE account_id = ANY($1)',
      [[sain, retire, expire, verrouille]],
    );
    // Le NOMBRE de lignes d'abord (un filtre qui rend zéro ligne « passe »
    // aussi un mauvais test), puis le contenu.
    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0]?.account_id).toBe(sain);
    expect(rows.rows[0]?.secret_hash).toBe(HASH);
  });

  test('C9 — le verrouillage retire structurellement le secret de la vue', async () => {
    const accountId = await createAccount();
    const id = await insertSecret(accountId);
    const before = await app.query(
      'SELECT id FROM authenticable_secrets WHERE account_id = $1',
      [accountId],
    );
    expect(before.rows).toHaveLength(1);
    await app.query(
      "UPDATE account_secrets SET locked_until = now() + interval '15 minutes' WHERE id = $1",
      [id],
    );
    const after = await app.query(
      'SELECT id FROM authenticable_secrets WHERE account_id = $1',
      [accountId],
    );
    expect(after.rows).toHaveLength(0);
  });

  test('standard D2 — INSERT explicitant status, created_at ou failed_attempts → permission denied', async () => {
    const accountId = await createAccount();
    await expect(
      app.query(
        "INSERT INTO account_secrets (account_id, secret_hash, status) VALUES ($1, $2, 'RETIRED')",
        [accountId, HASH],
      ),
    ).rejects.toThrow(/permission denied/);
    await expect(
      app.query(
        "INSERT INTO account_secrets (account_id, secret_hash, created_at) VALUES ($1, $2, '2019-01-01')",
        [accountId, HASH],
      ),
    ).rejects.toThrow(/permission denied/);
    await expect(
      app.query(
        'INSERT INTO account_secrets (account_id, secret_hash, failed_attempts) VALUES ($1, $2, 3)',
        [accountId, HASH],
      ),
    ).rejects.toThrow(/permission denied/);
  });
});
