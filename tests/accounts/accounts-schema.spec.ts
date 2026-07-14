import { Pool } from 'pg';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// Invariants de la migration 002, prouvés SOUS LE RÔLE BRIDÉ et hors
// transaction de test (CLAUDE.md §5). Les preuves « sous owner » vérifient
// que les TRIGGERS tiennent même quand les grants de colonne ne s'appliquent
// plus — la ceinture au-delà des bretelles.
describe('accounts — invariants en base', () => {
  let app: Pool;
  let owner: Pool;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    await truncateTables(owner, 'accounts');
  });

  afterAll(async () => {
    await truncateTables(owner, 'accounts');
    await app.end();
    await owner.end();
  });

  async function insertAccount(identifier: string): Promise<string> {
    const r = await app.query<{ id: string }>(
      "INSERT INTO accounts (public_identifier, role) VALUES ($1, 'ACCOUNT_HOLDER') RETURNING id",
      [identifier],
    );
    return firstRow(r).id;
  }

  test('INSERT valide sous rôle bridé → compte ACTIVE', async () => {
    const id = await insertAccount('1000000001');
    const row = firstRow(
      await app.query<{ status: string; deactivated_at: string | null }>(
        'SELECT status, deactivated_at FROM accounts WHERE id = $1',
        [id],
      ),
    );
    expect(row.status).toBe('ACTIVE');
    expect(row.deactivated_at).toBeNull();
  });

  test('doublon de public_identifier → refus base (unicité écosystème)', async () => {
    await insertAccount('1000000002');
    await expect(insertAccount('1000000002')).rejects.toThrow(
      /uq_accounts_public_identifier/,
    );
  });

  test('forme invalide (lettres, trop court, zéro de tête) → refus CHECK', async () => {
    await expect(insertAccount('ABC1234567')).rejects.toThrow(/chk_accounts_identifier_shape/);
    await expect(insertAccount('123')).rejects.toThrow(/chk_accounts_identifier_shape/);
    await expect(insertAccount('0123456789')).rejects.toThrow(/chk_accounts_identifier_shape/);
  });

  test('DELETE sous rôle bridé → permission denied (REVOKE)', async () => {
    const id = await insertAccount('1000000003');
    await expect(app.query('DELETE FROM accounts WHERE id = $1', [id])).rejects.toThrow(
      /permission denied/,
    );
  });

  test('TRUNCATE sous rôle bridé → permission denied (REVOKE)', async () => {
    await expect(app.query('TRUNCATE accounts')).rejects.toThrow(/permission denied/);
  });

  test('DELETE sous OWNER → le trigger tient (suppression interdite)', async () => {
    const id = await insertAccount('1000000004');
    await expect(owner.query('DELETE FROM accounts WHERE id = $1', [id])).rejects.toThrow(
      /suppression interdite/,
    );
  });

  test('mutation de public_identifier sous rôle bridé → permission denied (grant par colonne)', async () => {
    const id = await insertAccount('1000000005');
    await expect(
      app.query("UPDATE accounts SET public_identifier = '1999999999' WHERE id = $1", [id]),
    ).rejects.toThrow(/permission denied/);
  });

  test('mutation de public_identifier sous OWNER → le trigger tient (identité immuable)', async () => {
    const id = await insertAccount('1000000006');
    await expect(
      owner.query("UPDATE accounts SET public_identifier = '1999999998' WHERE id = $1", [id]),
    ).rejects.toThrow(/identité immuable/);
  });

  test('mutation du rôle sous OWNER → le trigger tient (identité immuable)', async () => {
    const id = await insertAccount('1000000007');
    await expect(
      owner.query("UPDATE accounts SET role = 'PLATFORM_ADMIN' WHERE id = $1", [id]),
    ).rejects.toThrow(/identité immuable/);
  });

  test('désactivation sous rôle bridé (statut seul) → la BASE pose l\'horodatage', async () => {
    const id = await insertAccount('1000000008');
    await app.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [id]);
    const row = firstRow(
      await app.query<{ status: string; age_seconds: number }>(
        `SELECT status, EXTRACT(EPOCH FROM (now() - deactivated_at))::float AS age_seconds
         FROM accounts WHERE id = $1`,
        [id],
      ),
    );
    expect(row.status).toBe('DEACTIVATED');
    expect(row.age_seconds).toBeLessThan(60);
  });

  test('D1a — date fantaisiste envoyée à la désactivation → ÉCRASÉE par now() (sous owner)', async () => {
    const id = await insertAccount('1000000009');
    await owner.query(
      "UPDATE accounts SET status = 'DEACTIVATED', deactivated_at = '2019-01-01' WHERE id = $1",
      [id],
    );
    const row = firstRow(
      await owner.query<{ age_seconds: number }>(
        `SELECT EXTRACT(EPOCH FROM (now() - deactivated_at))::float AS age_seconds
         FROM accounts WHERE id = $1`,
        [id],
      ),
    );
    // La ligne porte now(), pas 2019 : l'écrasement du trigger a eu lieu.
    expect(row.age_seconds).toBeLessThan(60);
  });

  test('D1b — re-datation d\'un compte désactivé sous rôle bridé → permission denied (colonne non accordée)', async () => {
    const id = await insertAccount('1000000010');
    await app.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [id]);
    await expect(
      app.query("UPDATE accounts SET deactivated_at = '2019-01-01' WHERE id = $1", [id]),
    ).rejects.toThrow(/permission denied/);
  });

  test('D1b — re-datation sous OWNER → le trigger tient (jamais réécrit)', async () => {
    const id = await insertAccount('1000000011');
    await owner.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [id]);
    await expect(
      owner.query("UPDATE accounts SET deactivated_at = '2019-01-01' WHERE id = $1", [id]),
    ).rejects.toThrow(/ne se réécrit jamais/);
  });

  test('D2 — INSERT explicitant created_at sous rôle bridé → permission denied', async () => {
    await expect(
      app.query(
        "INSERT INTO accounts (public_identifier, role, created_at) VALUES ('1000000012', 'ACCOUNT_HOLDER', '2019-01-01')",
      ),
    ).rejects.toThrow(/permission denied/);
  });

  test('D2 — INSERT explicitant status ou id sous rôle bridé → permission denied', async () => {
    await expect(
      app.query(
        "INSERT INTO accounts (public_identifier, role, status) VALUES ('1000000013', 'ACCOUNT_HOLDER', 'DEACTIVATED')",
      ),
    ).rejects.toThrow(/permission denied/);
    await expect(
      app.query(
        "INSERT INTO accounts (id, public_identifier, role) VALUES (gen_random_uuid(), '1000000014', 'ACCOUNT_HOLDER')",
      ),
    ).rejects.toThrow(/permission denied/);
  });

  test('réactivation DEACTIVATED → ACTIVE → refus trigger (transition non posée)', async () => {
    const id = await insertAccount('1000000015');
    await app.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [id]);
    await expect(
      app.query("UPDATE accounts SET status = 'ACTIVE' WHERE id = $1", [id]),
    ).rejects.toThrow(/interdit/);
  });
});
