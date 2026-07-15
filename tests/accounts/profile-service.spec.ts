import { Pool } from 'pg';
import { ProfileService } from '../../src/accounts/profile.service';
import { createAccount as createAccountFixture } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// Le profil de base, SOUS RÔLE BRIDÉ : sémantique PUT (remplacement), façade
// en miroir des CHECK de 011, et aucun log nulle part (le service n'en émet
// aucun — un nom est de la PII).
describe('ProfileService', () => {
  let app: Pool;
  let owner: Pool;
  let profiles: ProfileService;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    profiles = new ProfileService(app);
  });

  beforeEach(async () => {
    await truncateTables(owner, 'account_profiles', 'accounts');
  });

  afterAll(async () => {
    await app.end();
    await owner.end();
  });

  async function newAccount(): Promise<string> {
    seq += 1;
    return createAccountFixture(app, String(8400000000 + seq));
  }

  test('premier PUT → profil créé ; GET le rend tel quel', async () => {
    const accountId = await newAccount();
    const result = await profiles.replace(accountId, {
      displayName: 'Famille Kabila',
      locale: 'fr-CD',
    });
    expect(result.outcome).toBe('OK');
    expect(await profiles.get(accountId)).toEqual({
      displayName: 'Famille Kabila',
      locale: 'fr-CD',
    });
  });

  test('GET sans profil → champs nuls (un profil est OPTIONNEL)', async () => {
    const accountId = await newAccount();
    expect(await profiles.get(accountId)).toEqual({ displayName: null, locale: null });
  });

  test('PUT remplace : un champ absent s\'efface, et la BASE re-date updated_at', async () => {
    const accountId = await newAccount();
    await profiles.replace(accountId, { displayName: 'Famille Kabila', locale: 'fr-CD' });
    await owner.query(
      "UPDATE account_profiles SET updated_at = now() - interval '1 hour' WHERE account_id = $1",
      [accountId],
    );

    await profiles.replace(accountId, { displayName: 'Famille K.', locale: null });
    expect(await profiles.get(accountId)).toEqual({ displayName: 'Famille K.', locale: null });

    const row = firstRow(
      await owner.query<{ age_seconds: number }>(
        `SELECT EXTRACT(EPOCH FROM (now() - updated_at))::float AS age_seconds
           FROM account_profiles WHERE account_id = $1`,
        [accountId],
      ),
    );
    expect(row.age_seconds).toBeLessThan(60);
  });

  test('façade : nom hors borne ou locale difforme → refus PROPRE, rien n\'est écrit', async () => {
    const accountId = await newAccount();
    expect(
      (await profiles.replace(accountId, { displayName: 'x'.repeat(81), locale: null })).outcome,
    ).toBe('INVALID_DISPLAY_NAME');
    expect(
      (await profiles.replace(accountId, { displayName: '', locale: null })).outcome,
    ).toBe('INVALID_DISPLAY_NAME');
    expect(
      (await profiles.replace(accountId, { displayName: null, locale: 'FR_cd' })).outcome,
    ).toBe('INVALID_LOCALE');

    const count = firstRow(
      await owner.query<{ n: string }>('SELECT count(*) AS n FROM account_profiles'),
    );
    expect(Number(count.n)).toBe(0);
  });

  test('compte désactivé → ACCOUNT_NOT_ACTIVE (P0108 traduit, jamais un 500)', async () => {
    const accountId = await newAccount();
    await app.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [accountId]);
    expect(
      (await profiles.replace(accountId, { displayName: 'Fantôme', locale: null })).outcome,
    ).toBe('ACCOUNT_NOT_ACTIVE');
  });

  test('BOLA : le service ne touche QUE le profil du compte nommé par le jeton', async () => {
    const a = await newAccount();
    const b = await newAccount();
    await profiles.replace(a, { displayName: 'Compte A', locale: 'fr' });
    await profiles.replace(b, { displayName: 'Compte B', locale: 'sw' });
    expect((await profiles.get(a)).displayName).toBe('Compte A');
    expect((await profiles.get(b)).displayName).toBe('Compte B');
  });
});
