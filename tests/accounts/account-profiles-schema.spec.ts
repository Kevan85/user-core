import { Pool } from 'pg';
import { createAccount as createAccountFixture } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// Invariants de la migration 011 (volet profil), sous rôle bridé ET owner.
// Le profil est la seule table MUTABLE du dépôt — mutable ne veut pas dire
// sans loi : rattachement immuable, horodatages posés par la base, zéro
// suppression.
describe('account_profiles — invariants en base', () => {
  let app: Pool;
  let owner: Pool;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    await truncateTables(owner, 'account_profiles', 'accounts');
  });

  afterAll(async () => {
    await truncateTables(owner, 'account_profiles', 'accounts');
    await app.end();
    await owner.end();
  });

  async function newAccount(): Promise<string> {
    seq += 1;
    return createAccountFixture(app, String(8200000000 + seq));
  }

  async function insertProfile(
    accountId: string,
    displayName: string | null = 'Famille Test',
    locale: string | null = 'fr-CD',
  ): Promise<void> {
    await app.query(
      'INSERT INTO account_profiles (account_id, display_name, locale) VALUES ($1, $2, $3)',
      [accountId, displayName, locale],
    );
  }

  test('INSERT sous rôle bridé → profil posé, horodatages de la base', async () => {
    const accountId = await newAccount();
    await insertProfile(accountId);
    const row = firstRow(
      await app.query<{ display_name: string; locale: string; age_seconds: number }>(
        `SELECT display_name, locale,
                EXTRACT(EPOCH FROM (now() - created_at))::float AS age_seconds
           FROM account_profiles WHERE account_id = $1`,
        [accountId],
      ),
    );
    expect(row.display_name).toBe('Famille Test');
    expect(row.locale).toBe('fr-CD');
    expect(row.age_seconds).toBeLessThan(60);
  });

  test('les deux champs sont OPTIONNELS (un profil vide est un profil)', async () => {
    const accountId = await newAccount();
    await expect(insertProfile(accountId, null, null)).resolves.toBeUndefined();
  });

  test('au plus UN profil par compte (clé primaire = account_id)', async () => {
    const accountId = await newAccount();
    await insertProfile(accountId);
    await expect(insertProfile(accountId)).rejects.toThrow(/account_profiles_pkey/);
  });

  test('aucun profil ne naît sous un compte désactivé (P0108)', async () => {
    const accountId = await newAccount();
    await app.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [accountId]);
    await expect(insertProfile(accountId)).rejects.toMatchObject({ code: 'P0108' });
  });

  test('nom vide ou hors borne, locale difforme → refus CHECK', async () => {
    const accountId = await newAccount();
    await expect(insertProfile(accountId, '')).rejects.toThrow(
      /chk_account_profiles_display_name/,
    );
    await expect(insertProfile(accountId, 'x'.repeat(81))).rejects.toThrow(
      /chk_account_profiles_display_name/,
    );
    await expect(insertProfile(accountId, 'Famille', 'FR_cd')).rejects.toThrow(
      /chk_account_profiles_locale/,
    );
  });

  test('mutation légitime sous rôle bridé : la BASE re-date updated_at', async () => {
    const accountId = await newAccount();
    await insertProfile(accountId);
    await owner.query(
      "UPDATE account_profiles SET updated_at = now() - interval '1 hour' WHERE account_id = $1",
      [accountId],
    );
    await app.query("UPDATE account_profiles SET display_name = 'Nouveau Nom' WHERE account_id = $1", [
      accountId,
    ]);
    const row = firstRow(
      await app.query<{ display_name: string; age_seconds: number }>(
        `SELECT display_name,
                EXTRACT(EPOCH FROM (now() - updated_at))::float AS age_seconds
           FROM account_profiles WHERE account_id = $1`,
        [accountId],
      ),
    );
    expect(row.display_name).toBe('Nouveau Nom');
    expect(row.age_seconds).toBeLessThan(60);
  });

  test('rattachement immuable : re-pointer un profil vers un autre compte → P0101 (owner)', async () => {
    const a = await newAccount();
    const b = await newAccount();
    await insertProfile(a);
    await expect(
      owner.query('UPDATE account_profiles SET account_id = $2 WHERE account_id = $1', [a, b]),
    ).rejects.toMatchObject({ code: 'P0101' });
  });

  test('created_at et updated_at ne s\'écrivent pas depuis le rôle bridé (grant par colonne)', async () => {
    const accountId = await newAccount();
    await insertProfile(accountId);
    await expect(
      app.query("UPDATE account_profiles SET created_at = '2019-01-01' WHERE account_id = $1", [
        accountId,
      ]),
    ).rejects.toThrow(/permission denied/);
    await expect(
      app.query(
        "INSERT INTO account_profiles (account_id, display_name, locale, created_at) VALUES ($1, 'X', 'fr', '2019-01-01')",
        [await newAccount()],
      ),
    ).rejects.toThrow(/permission denied/);
  });

  test('DELETE : rôle bridé → permission denied ; owner → forbid_delete tient (P0107)', async () => {
    const accountId = await newAccount();
    await insertProfile(accountId);
    await expect(
      app.query('DELETE FROM account_profiles WHERE account_id = $1', [accountId]),
    ).rejects.toThrow(/permission denied/);
    await expect(
      owner.query('DELETE FROM account_profiles WHERE account_id = $1', [accountId]),
    ).rejects.toMatchObject({ code: 'P0107' });
  });
});
