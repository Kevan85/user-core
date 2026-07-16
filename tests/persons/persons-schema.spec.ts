import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import {
  decryptCivilIdentity,
  encryptCivilIdentity,
  generateErasureSalt,
} from '../../src/crypto/person-identity';
import { DB_ERROR, dbErrorCode } from '../../src/db/errors';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';
import { createPerson } from '../helpers/persons';

// Invariants de 014, sous rôle bridé ET sous owner (le standard du dépôt) :
// les triggers doivent tenir au-delà des droits.
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

async function codeOf(run: () => Promise<unknown>): Promise<string | undefined> {
  try {
    await run();
  } catch (err) {
    return dbErrorCode(err);
  }
  throw new Error("une violation était attendue : la garde n'a pas levé");
}

describe('persons — invariants en base (014)', () => {
  let app: Pool;
  let owner: Pool;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    await truncateTables(owner, 'persons');
  });

  afterAll(async () => {
    await truncateTables(owner, 'persons');
    await app.end();
    await owner.end();
  });

  function nextIdentifier(): string {
    seq += 1;
    return String(8_200_000_000 + seq);
  }

  test('création par le chemin unique (rôle bridé), identité optionnelle à la naissance', async () => {
    const id = await createPerson(app, nextIdentifier());
    const row = firstRow(
      await app.query<{ public_identifier: string; enc_key_id: string | null; birth_year: number | null }>(
        'SELECT public_identifier, enc_key_id, birth_year FROM persons WHERE id = $1',
        [id],
      ),
    );
    expect(row.enc_key_id).toBeNull();
    expect(row.birth_year).toBeNull();
  });

  test("l'INSERT direct n'existe pas pour le rôle applicatif — et n'a jamais existé", async () => {
    await expect(
      app.query(
        'INSERT INTO persons (public_identifier, erasure_salt) VALUES ($1, $2)',
        [nextIdentifier(), generateErasureSalt()],
      ),
    ).rejects.toThrow(/permission denied/);
  });

  test('forme de l’identifiant public et unicité : tranchées par la base', async () => {
    await expect(createPerson(app, 'pas-un-identifiant')).rejects.toThrow(
      /chk_persons_identifier_shape/,
    );
    const identifier = nextIdentifier();
    await createPerson(app, identifier);
    await expect(createPerson(app, identifier)).rejects.toThrow(
      /uq_persons_public_identifier/,
    );
  });

  test('le blob et sa clé vivent et meurent ensemble (paire CHECK)', async () => {
    const salt = generateErasureSalt();
    const enc = encryptCivilIdentity(crypto.encryption, salt, IDENTITY);
    // Blob sans clé : refusé.
    await expect(
      app.query('SELECT create_person($1, $2, $3, $4, $5)', [
        nextIdentifier(),
        salt,
        enc.token,
        null,
        null,
      ]),
    ).rejects.toThrow(/chk_persons_identity_pair/);
    // Clé sans blob : refusé.
    await expect(
      app.query('SELECT create_person($1, $2, $3, $4, $5)', [
        nextIdentifier(),
        salt,
        null,
        enc.encKeyId,
        null,
      ]),
    ).rejects.toThrow(/chk_persons_identity_pair/);
  });

  test('le sel d’effacement fait 32 octets, ni plus ni moins', async () => {
    await expect(
      app.query('SELECT create_person($1, $2, $3, $4, $5)', [
        nextIdentifier(),
        randomBytes(16),
        null,
        null,
        null,
      ]),
    ).rejects.toThrow(/chk_persons_erasure_salt_size/);
  });

  test('année de naissance future : refusée par la base, sous le rôle bridé ET sous owner', async () => {
    const nextYear = new Date().getUTCFullYear() + 1;
    await expect(
      codeOf(() => createPerson(app, nextIdentifier(), { birthYear: nextYear })),
    ).resolves.toBe(DB_ERROR.VALUE_OUT_OF_BOUNDS);
    // L'owner contourne les GRANT, jamais les triggers.
    await expect(
      codeOf(() =>
        owner.query('INSERT INTO persons (public_identifier, erasure_salt, birth_year) VALUES ($1, $2, $3)', [
          nextIdentifier(),
          generateErasureSalt(),
          nextYear,
        ]),
      ),
    ).resolves.toBe(DB_ERROR.VALUE_OUT_OF_BOUNDS);
  });

  test('birth_year est SET-ONCE : posé une fois, plus jamais retouché — même par owner', async () => {
    const id = await createPerson(app, nextIdentifier());
    // NULL -> valeur : permis, une fois (rôle bridé).
    await app.query('UPDATE persons SET birth_year = 2010 WHERE id = $1', [id]);
    // Retouche : refusée, sous rôle bridé ET sous owner.
    await expect(
      codeOf(() => app.query('UPDATE persons SET birth_year = 2011 WHERE id = $1', [id])),
    ).resolves.toBe(DB_ERROR.IMMUTABLE);
    await expect(
      codeOf(() => owner.query('UPDATE persons SET birth_year = 2011 WHERE id = $1', [id])),
    ).resolves.toBe(DB_ERROR.IMMUTABLE);
    // Retour à NULL : refusé aussi — la borne d'âge est un registre.
    await expect(
      codeOf(() => owner.query('UPDATE persons SET birth_year = NULL WHERE id = $1', [id])),
    ).resolves.toBe(DB_ERROR.IMMUTABLE);
  });

  test('identité technique immuable (sel, identifiant, created_at) — même pour owner', async () => {
    const id = await createPerson(app, nextIdentifier());
    await expect(
      codeOf(() =>
        owner.query('UPDATE persons SET erasure_salt = $2 WHERE id = $1', [
          id,
          generateErasureSalt(),
        ]),
      ),
    ).resolves.toBe(DB_ERROR.IMMUTABLE);
    await expect(
      codeOf(() =>
        owner.query('UPDATE persons SET public_identifier = $2 WHERE id = $1', [
          id,
          nextIdentifier(),
        ]),
      ),
    ).resolves.toBe(DB_ERROR.IMMUTABLE);
    await expect(
      codeOf(() => owner.query("UPDATE persons SET created_at = now() - INTERVAL '1 day' WHERE id = $1", [id])),
    ).resolves.toBe(DB_ERROR.IMMUTABLE);
  });

  test('zéro suppression : refusée au rôle bridé (droit) ET à owner (trigger)', async () => {
    const id = await createPerson(app, nextIdentifier());
    await expect(app.query('DELETE FROM persons WHERE id = $1', [id])).rejects.toThrow(
      /permission denied/,
    );
    await expect(
      codeOf(() => owner.query('DELETE FROM persons WHERE id = $1', [id])),
    ).resolves.toBe(DB_ERROR.DELETE_FORBIDDEN);
  });

  test('le blob et le sel sont ILLISIBLES au rôle applicatif (colonnes et SELECT *)', async () => {
    await expect(app.query('SELECT civil_identity_encrypted FROM persons')).rejects.toThrow(
      /permission denied/,
    );
    await expect(app.query('SELECT erasure_salt FROM persons')).rejects.toThrow(
      /permission denied/,
    );
    await expect(app.query('SELECT * FROM persons')).rejects.toThrow(/permission denied/);
    // Les colonnes de gestion, elles, restent lisibles.
    await expect(
      app.query('SELECT id, public_identifier, enc_key_id, birth_year FROM persons'),
    ).resolves.toBeDefined();
  });

  test('updated_at est posé par la base : la valeur du client est écrasée', async () => {
    const id = await createPerson(app, nextIdentifier());
    await owner.query("UPDATE persons SET updated_at = '2000-01-01T00:00:00Z' WHERE id = $1", [id]);
    const row = firstRow(
      await app.query<{ age_seconds: number }>(
        'SELECT EXTRACT(EPOCH FROM (now() - updated_at))::float AS age_seconds FROM persons WHERE id = $1',
        [id],
      ),
    );
    expect(row.age_seconds).toBeLessThan(5);
  });

  test('aller-retour complet : create_person + read_person_identity + déchiffrement', async () => {
    const salt = generateErasureSalt();
    const enc = encryptCivilIdentity(crypto.encryption, salt, IDENTITY);
    const id = await createPerson(app, nextIdentifier(), { erasureSalt: salt, encrypted: enc });

    // La colonne en clair et le blob viennent de la MÊME date, par le même
    // écrivain (src/crypto/person-identity.ts) — la base ne peut pas tenir
    // cette cohérence, la discipline du seul écrivain s'en charge.
    const stored = firstRow(
      await app.query<{ birth_year: number; enc_key_id: string }>(
        'SELECT birth_year, enc_key_id FROM persons WHERE id = $1',
        [id],
      ),
    );
    expect(stored.birth_year).toBe(2010);
    expect(stored.enc_key_id).toBe('E1');

    const identity = firstRow(
      await app.query<{
        civil_identity_encrypted: string;
        enc_key_id: string;
        erasure_salt: Buffer;
      }>('SELECT * FROM read_person_identity($1)', [id]),
    );
    expect(identity.erasure_salt.equals(salt)).toBe(true);
    expect(
      decryptCivilIdentity(crypto.encryption, identity.erasure_salt, identity.civil_identity_encrypted),
    ).toEqual(IDENTITY);
  });
});

describe('emancipation_policy — la politique appartient aux migrations (014)', () => {
  let app: Pool;
  let owner: Pool;

  beforeAll(() => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
  });

  afterAll(async () => {
    await app.end();
    await owner.end();
  });

  test('le seuil par défaut est 16 (décision Kevin, paramétrable par migration signée)', async () => {
    const row = firstRow(
      await app.query<{ age: number }>('SELECT emancipation_minimum_age() AS age'),
    );
    expect(row.age).toBe(16);
  });

  test('le rôle applicatif lit la politique, il ne l’écrit JAMAIS', async () => {
    await expect(
      app.query('UPDATE emancipation_policy SET minimum_age_years = 5'),
    ).rejects.toThrow(/permission denied/);
    await expect(
      app.query('INSERT INTO emancipation_policy (singleton, minimum_age_years) VALUES (false, 5)'),
    ).rejects.toThrow(/permission denied/);
  });

  test('UNE ligne, pour toujours : le singleton ne se duplique pas, même par owner', async () => {
    await expect(
      owner.query('INSERT INTO emancipation_policy (singleton, minimum_age_years) VALUES (true, 18)'),
    ).rejects.toThrow(/duplicate key/);
    await expect(
      owner.query('INSERT INTO emancipation_policy (singleton, minimum_age_years) VALUES (false, 18)'),
    ).rejects.toThrow(/emancipation_policy_singleton_check/);
  });

  test('les bornes de saisie tiennent : un 160 ne passe pas, même par owner', async () => {
    await expect(
      owner.query('UPDATE emancipation_policy SET minimum_age_years = 160'),
    ).rejects.toThrow(/minimum_age_years/);
  });
});
