import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { encrypt } from '../../src/crypto/aes-gcm';
import { fingerprintOf } from '../../src/crypto/fingerprint';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { DB_ERROR, dbErrorCode } from '../../src/db/errors';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// Invariants de 006, sous rôle bridé ET sous owner (le standard du dépôt).
// La clé d'empreinte active du SCHÉMA est « H1 » (migration 006) : le
// trousseau de test la nomme pareil — c'est le contrat.
const crypto = assembleCryptoFromEnv({
  USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
  USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
  USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
  USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
});

async function codeOf(run: () => Promise<unknown>): Promise<string | undefined> {
  try {
    await run();
  } catch (err) {
    return dbErrorCode(err);
  }
  throw new Error('une violation était attendue : la garde n\'a pas levé');
}

describe('phone_claims — invariants en base', () => {
  let app: Pool;
  let owner: Pool;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    await truncateTables(owner, 'phone_claims', 'accounts');
  });

  afterAll(async () => {
    await truncateTables(owner, 'phone_claims', 'accounts');
    await app.end();
    await owner.end();
  });

  async function newAccount(): Promise<string> {
    seq += 1;
    return firstRow(
      await app.query<{ id: string }>(
        "INSERT INTO accounts (public_identifier, role) VALUES ($1, 'ACCOUNT_HOLDER') RETURNING id",
        [String(7100000000 + seq)],
      ),
    ).id;
  }

  function phoneFields(phone: string): [string, string, string, string] {
    const fp = fingerprintOf(crypto.fingerprint, phone);
    const token = encrypt(crypto.encryption, phone);
    return [fp.value, fp.hmacKeyId, token, crypto.encryption.activeKeyId];
  }

  async function declare(accountId: string, phone: string, client: Pool = app): Promise<string> {
    const r = await client.query<{ id: string }>(
      `INSERT INTO phone_claims (account_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
       VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      [accountId, ...phoneFields(phone)],
    );
    return firstRow(r).id;
  }

  // Promotion ACTIVE/PROVEN : réservée à l'OWNER — c'est exactement le point
  // (le rôle applicatif ne peut pas écrire assurance_level, donc ne peut PAS
  // activer une revendication ; seule la fonction de vérification le pourra).
  async function proveUnderOwner(claimId: string): Promise<void> {
    await owner.query(
      "UPDATE phone_claims SET status = 'ACTIVE', assurance_level = 'PROVEN' WHERE id = $1",
      [claimId],
    );
  }

  test('déclaration : PENDING/DECLARED, ni vérifiée ni révoquée, le clair nulle part', async () => {
    const accountId = await newAccount();
    const id = await declare(accountId, '+243810000001');
    const row = firstRow(
      await app.query<{ status: string; assurance_level: string; verified_at: string | null; phone_hmac: string }>(
        'SELECT status, assurance_level, verified_at, phone_hmac FROM phone_claims WHERE id = $1',
        [id],
      ),
    );
    expect(row.status).toBe('PENDING');
    expect(row.assurance_level).toBe('DECLARED');
    expect(row.verified_at).toBeNull();
    expect(row.phone_hmac).not.toContain('810000001');
  });

  test('phone_encrypted est ILLISIBLE au rôle applicatif (colonne et SELECT *)', async () => {
    await expect(app.query('SELECT phone_encrypted FROM phone_claims')).rejects.toThrow(
      /permission denied/,
    );
    await expect(app.query('SELECT * FROM phone_claims')).rejects.toThrow(/permission denied/);
    // Les colonnes de gestion, elles, restent lisibles.
    await expect(
      app.query('SELECT id, status, phone_hmac, hmac_key_id FROM phone_claims'),
    ).resolves.toBeDefined();
  });

  test('le service ne peut PAS activer une revendication (assurance_level hors GRANT)', async () => {
    const id = await declare(await newAccount(), '+243810000002');
    await expect(
      app.query("UPDATE phone_claims SET assurance_level = 'PROVEN' WHERE id = $1", [id]),
    ).rejects.toThrow(/permission denied/);
    // Et sans PROVEN, l'activation est refusée par le trigger (CHECK/garde) :
    // « actif mais non prouvé » est non représentable.
    await expect(
      codeOf(() => app.query("UPDATE phone_claims SET status = 'ACTIVE' WHERE id = $1", [id])),
    ).resolves.toBe(DB_ERROR.FORBIDDEN_TRANSITION);
  });

  test('activation (owner) : la base horodate verified_at elle-même', async () => {
    const id = await declare(await newAccount(), '+243810000003');
    await proveUnderOwner(id);
    const row = firstRow(
      await app.query<{ status: string; age_seconds: number }>(
        `SELECT status, EXTRACT(EPOCH FROM (now() - verified_at))::float AS age_seconds
         FROM phone_claims WHERE id = $1`,
        [id],
      ),
    );
    expect(row.status).toBe('ACTIVE');
    expect(row.age_seconds).toBeLessThan(60);
  });

  test('UNICITÉ MONDIALE : deux revendications ACTIVE de la MÊME ligne → refus', async () => {
    const phone = '+243810000004';
    const first = await declare(await newAccount(), phone);
    await proveUnderOwner(first);

    const second = await declare(await newAccount(), phone); // PENDING : autorisé
    await expect(proveUnderOwner(second)).rejects.toThrow(/uq_phone_claims_active_line/);
    // (Le numéro recyclé — révoquer la première PUIS activer la seconde —
    // sera géré par la cascade « preuve fraîche gagne » en 007.)
  });

  test('Q3 — une seule revendication VIVANTE par compte', async () => {
    const accountId = await newAccount();
    await declare(accountId, '+243810000005');
    await expect(declare(accountId, '+243810000006')).rejects.toThrow(
      /uq_phone_claims_alive_per_account/,
    );
    // Le chemin légitime : révoquer (REPLACED) puis déclarer l'autre.
    await app.query(
      "UPDATE phone_claims SET status = 'REVOKED', revoke_reason = 'REPLACED' WHERE account_id = $1 AND status = 'PENDING'",
      [accountId],
    );
    await expect(declare(accountId, '+243810000006')).resolves.toBeDefined();
  });

  test('Q2 — une empreinte calculée sous une clé NON active est refusée (P0109)', async () => {
    const accountId = await newAccount();
    const [hmac, , encrypted, encKeyId] = phoneFields('+243810000007');
    await expect(
      codeOf(() =>
        app.query(
          `INSERT INTO phone_claims (account_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
           VALUES ($1, $2, 'H0_PERIMEE', $3, $4)`,
          [accountId, hmac, encrypted, encKeyId],
        ),
      ),
    ).resolves.toBe(DB_ERROR.STALE_FINGERPRINT_KEY);
  });

  test('la référence de clé HMAC est INALTÉRABLE par le service (rotation = migration signée)', async () => {
    const row = firstRow(
      await app.query<{ hmac_key_id: string }>('SELECT hmac_key_id FROM hmac_key_reference'),
    );
    expect(row.hmac_key_id).toBe('H1');
    await expect(
      app.query("UPDATE hmac_key_reference SET hmac_key_id = 'H2'"),
    ).rejects.toThrow(/permission denied/);
    await expect(
      app.query("INSERT INTO hmac_key_reference (singleton, hmac_key_id) VALUES (false, 'H2')"),
    ).rejects.toThrow(/permission denied/);
  });

  test('le niveau de preuve ne DESCEND jamais (P0102, sous owner)', async () => {
    const id = await declare(await newAccount(), '+243810000008');
    await proveUnderOwner(id);
    await expect(
      codeOf(() =>
        owner.query("UPDATE phone_claims SET assurance_level = 'DECLARED' WHERE id = $1", [id]),
      ),
    ).resolves.toBe(DB_ERROR.FORBIDDEN_TRANSITION);
  });

  test('contenu immuable (P0101) et ligne révoquée figée (P0103), sous owner', async () => {
    const id = await declare(await newAccount(), '+243810000009');
    await expect(
      codeOf(() =>
        owner.query("UPDATE phone_claims SET phone_hmac = 'autre' WHERE id = $1", [id]),
      ),
    ).resolves.toBe(DB_ERROR.IMMUTABLE);

    await app.query(
      "UPDATE phone_claims SET status = 'REVOKED', revoke_reason = 'ADMIN' WHERE id = $1",
      [id],
    );
    await expect(
      codeOf(() => owner.query("UPDATE phone_claims SET status = 'ACTIVE' WHERE id = $1", [id])),
    ).resolves.toBe(DB_ERROR.FROZEN_ROW);
  });

  test('révocation sans motif → refus ; horodatage posé par la base', async () => {
    const id = await declare(await newAccount(), '+243810000010');
    await expect(
      codeOf(() => app.query("UPDATE phone_claims SET status = 'REVOKED' WHERE id = $1", [id])),
    ).resolves.toBe(DB_ERROR.FORBIDDEN_TRANSITION);
  });

  test('DELETE : rôle bridé → permission denied ; owner → P0107', async () => {
    const id = await declare(await newAccount(), '+243810000011');
    await expect(app.query('DELETE FROM phone_claims WHERE id = $1', [id])).rejects.toThrow(
      /permission denied/,
    );
    await expect(
      codeOf(() => owner.query('DELETE FROM phone_claims WHERE id = $1', [id])),
    ).resolves.toBe(DB_ERROR.DELETE_FORBIDDEN);
    await expect(app.query('TRUNCATE phone_claims')).rejects.toThrow(/permission denied/);
  });

  test('cascade C13 étendue : compte désactivé → revendication révoquée par la BASE', async () => {
    const accountId = await newAccount();
    const id = await declare(accountId, '+243810000012');
    await proveUnderOwner(id);

    await app.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [accountId]);

    const claims = await app.query<{ status: string; revoke_reason: string }>(
      'SELECT status, revoke_reason FROM phone_claims WHERE account_id = $1',
      [accountId],
    );
    expect(claims.rows).toHaveLength(1);
    expect(claims.rows[0]?.status).toBe('REVOKED');
    expect(claims.rows[0]?.revoke_reason).toBe('ACCOUNT_DEACTIVATED');
  });
});
