import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { IdentityService } from '../../src/accounts/identity.service';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { encryptCivilIdentity } from '../../src/crypto/person-identity';
import { createAccount } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// Le PREMIER APPELANT du blob d'identité civile (étape 3) — sous rôle bridé,
// contre le vrai Postgres. C'est ici que C7 se prouve en situation : une
// violation d'intégrité du registre ne ressemble JAMAIS à une faute de saisie.
const crypto = assembleCryptoFromEnv({
  USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
  USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
  USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
  USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
});

const IDENTITY = {
  nameComponents: ['Kabeya', 'Mwamba', 'Junior'],
  displayName: 'Kabeya Mwamba',
  birthDate: '2010-03-12',
};

describe('IdentityService — fournir et lire son identité civile', () => {
  let app: Pool;
  let owner: Pool;
  let service: IdentityService;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    service = new IdentityService(app, crypto);
    await truncateTables(owner, 'accounts', 'persons');
  });

  afterAll(async () => {
    await truncateTables(owner, 'accounts', 'persons');
    await app.end();
    await owner.end();
  });

  async function newAccount(): Promise<string> {
    seq += 1;
    return createAccount(app, String(8_400_000_000 + seq));
  }

  test('avant toute fourniture : NOT_PROVIDED (minimisation — rien à l’inscription)', async () => {
    const accountId = await newAccount();
    await expect(service.read(accountId)).resolves.toEqual({ outcome: 'NOT_PROVIDED' });
  });

  test('fournir puis relire : aller-retour fidèle, blob et borne posés en base', async () => {
    const accountId = await newAccount();
    const provided = await service.provide(accountId, IDENTITY);
    expect(provided.outcome).toBe('OK');

    await expect(service.read(accountId)).resolves.toEqual({ outcome: 'OK', identity: IDENTITY });

    const stored = firstRow(
      await app.query<{ birth_year: number; enc_key_id: string }>(
        `SELECT p.birth_year, p.enc_key_id FROM persons p
          JOIN accounts a ON a.person_id = p.id WHERE a.id = $1`,
        [accountId],
      ),
    );
    expect(stored.birth_year).toBe(2010);
    expect(stored.enc_key_id).toBe('E1');
  });

  test('corriger une faute de frappe (même année) : permis — le blob est mutable, pas la borne', async () => {
    const accountId = await newAccount();
    await service.provide(accountId, IDENTITY);
    const corrected = { ...IDENTITY, nameComponents: ['Kabeya', 'Mwamba', 'Junior-Emmanuel'] };
    await expect(service.provide(accountId, corrected)).resolves.toEqual({
      outcome: 'OK',
      identity: corrected,
    });
    await expect(service.read(accountId)).resolves.toEqual({ outcome: 'OK', identity: corrected });
  });

  test("changer d'ANNÉE de naissance : BIRTH_DATE_LOCKED (le set-once de 014 est le mur, ceci est la façade)", async () => {
    const accountId = await newAccount();
    await service.provide(accountId, IDENTITY);
    await expect(
      service.provide(accountId, { ...IDENTITY, birthDate: '2011-03-12' }),
    ).resolves.toEqual({ outcome: 'BIRTH_DATE_LOCKED' });
    // Rien n'a bougé : ni le blob, ni la borne.
    await expect(service.read(accountId)).resolves.toEqual({ outcome: 'OK', identity: IDENTITY });
  });

  test('identité invalide : INVALID avec la raison du module (sans PII), rien d’écrit', async () => {
    const accountId = await newAccount();
    const result = await service.provide(accountId, { ...IDENTITY, birthDate: '2999-01-01' });
    if (result.outcome !== 'INVALID') {
      throw new Error(`INVALID attendu, reçu ${result.outcome}`);
    }
    expect(result.reason).toMatch(/dans le futur/);
    expect(result.reason).not.toContain('2999');
    await expect(service.read(accountId)).resolves.toEqual({ outcome: 'NOT_PROVIDED' });
  });

  test('C7 en situation : une divergence fabriquée rend INTEGRITY_VIOLATION tracée — JAMAIS une erreur de saisie', async () => {
    const accountId = await newAccount();
    await service.provide(accountId, IDENTITY); // 2010

    // Écriture partielle fabriquée : le blob repart avec une autre date, la
    // borne reste à 2010 (le set-once ne voit rien — c'est tout le point).
    const stored = firstRow(
      await app.query<{ person_id: string; erasure_salt: Buffer }>(
        `SELECT a.person_id, r.erasure_salt FROM accounts a,
                LATERAL read_person_identity(a.person_id) r
          WHERE a.id = $1`,
        [accountId],
      ),
    );
    const divergent = encryptCivilIdentity(crypto.encryption, stored.erasure_salt, {
      ...IDENTITY,
      birthDate: '2004-03-12',
    });
    await owner.query(
      'UPDATE persons SET civil_identity_encrypted = $2, enc_key_id = $3 WHERE id = $1',
      [stored.person_id, divergent.token, divergent.encKeyId],
    );

    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      // Le verdict est DISTINCT (pas un INVALID, pas une exception de
      // formulaire) : l'appelant HTTP en fera un 500, jamais un 400.
      await expect(service.read(accountId)).resolves.toEqual({
        outcome: 'INTEGRITY_VIOLATION',
      });
      // Et l'incident est OBSERVABLE : trace émise (espion), sans PII.
      expect(errorSpy).toHaveBeenCalledTimes(1);
      const traced = String(errorSpy.mock.calls[0]?.[0]);
      expect(traced).toMatch(/^INTÉGRITÉ :/);
      expect(traced).not.toContain('2004');
      expect(traced).not.toContain('Kabeya');
    } finally {
      errorSpy.mockRestore();
    }
  });
});
