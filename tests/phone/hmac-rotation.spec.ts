import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { encrypt } from '../../src/crypto/aes-gcm';
import { fingerprintOf, fingerprintUnder } from '../../src/crypto/fingerprint';
import { assembleKeyringsFromEnv } from '../../src/crypto/keyring';
import { DB_ERROR, dbErrorCode } from '../../src/db/errors';
import { resolveVerifiedAddress } from '../../src/phone/verified-address';
import { rotatePhoneHmacKey } from '../../scripts/rotate-phone-hmac';
import { createAccount } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';
import { fullKeyringEnv } from '../helpers/keyring-env';

/**
 * 025 + rotate-phone-hmac (étape 4e) — LE CAS DUR : la rotation de la clé
 * d'empreinte. Ce que cette suite prouve :
 *   1. LE MUR (C1) : la référence ne bascule pas tant qu'une revendication
 *      ACTIVE vit sous une autre clé — une rotation INTERROMPUE au milieu ne
 *      peut pas laisser un état à deux clés référencé (P0115) ;
 *   2. le script fait une VRAIE rotation : re-hachage intégral, unicité
 *      préservée, intégrité re-dérivée AVANT re-signature, bascule en dernier ;
 *   3. le filet du DISABLE TRIGGER USER : les triggers sont réarmés
 *      (pg_trigger.tgenabled = 'O'), vérifié à chaque CI ;
 *   4. après bascule, une déclaration sous l'ancienne clé refuse (P0109).
 *
 * La référence est un SINGLETON de la base partagée : la suite la RESTAURE
 * sur H1 en afterAll (exécution sérialisée, maxWorkers: 1 — jest.config.js).
 */
const H1 = randomBytes(32).toString('base64');
const H2 = randomBytes(32).toString('base64');

const before = assembleKeyringsFromEnv(
  fullKeyringEnv({
    USER_CORE_HMAC_KEYS: JSON.stringify({ H1 }),
    USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
  }),
);
// Le déploiement de rotation : H2 signe, H1 reste lisible — MÊMES matériaux.
const after = assembleKeyringsFromEnv(
  fullKeyringEnv({
    USER_CORE_ENC_KEYS: JSON.stringify({
      E1: before.encryption.active().material.toString('base64'),
    }),
    USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
    USER_CORE_HMAC_KEYS: JSON.stringify({ H1, H2 }),
    USER_CORE_HMAC_ACTIVE_KEY_ID: 'H2',
  }),
);

describe('4e — rotation de la clé d\'empreinte : le mur, puis le script', () => {
  let app: Pool;
  let owner: Pool;
  let seq = 0;

  const TABLES = [
    'account_notifications',
    'outbox',
    'possession_proofs',
    'phone_claims',
    'person_responsibilities',
    'accounts',
    'persons',
  ];

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    await truncateTables(owner, ...TABLES);
  });

  afterAll(async () => {
    // RESTAURATION du singleton partagé : plus aucune ACTIVE, la référence
    // revient sur H1 (le mur 025 l'autorise) — les autres suites en dépendent.
    await truncateTables(owner, ...TABLES);
    await owner.query(
      "UPDATE hmac_key_reference SET hmac_key_id = 'H1', rotated_at = now() WHERE singleton",
    );
    await app.end();
    await owner.end();
  });

  function nextIdentifier(): string {
    seq += 1;
    return String(8_760_000_000 + seq);
  }

  async function activeClaim(phone: string): Promise<string> {
    const accountId = await createAccount(app, nextIdentifier());
    const personId = firstRow(
      await app.query<{ person_id: string }>('SELECT person_id FROM accounts WHERE id = $1', [
        accountId,
      ]),
    ).person_id;
    const fp = fingerprintOf(before.fingerprint, phone);
    const claimId = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO phone_claims (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [
          personId,
          fp.value,
          fp.hmacKeyId,
          encrypt(before.encryption, phone),
          before.encryption.activeKeyId,
        ],
      ),
    ).id;
    await owner.query(
      "UPDATE phone_claims SET status = 'ACTIVE', assurance_level = 'PROVEN' WHERE id = $1",
      [claimId],
    );
    return claimId;
  }

  async function codeOf(run: () => Promise<unknown>): Promise<string | undefined> {
    try {
      await run();
    } catch (err) {
      return dbErrorCode(err);
    }
    throw new Error("une violation était attendue : la garde n'a pas levé");
  }

  test('LE MUR (C1) : une rotation interrompue au milieu ne bascule JAMAIS la référence (P0115)', async () => {
    const first = await activeClaim('+8801700000301');
    await activeClaim('+8801700000302');

    // Bascule directe, rien re-haché : refusée — même sous owner.
    await expect(
      codeOf(() =>
        owner.query("UPDATE hmac_key_reference SET hmac_key_id = 'H2' WHERE singleton"),
      ),
    ).resolves.toBe(DB_ERROR.ROTATION_INCOMPLETE);

    // Rotation INTERROMPUE : une ligne sur deux re-hachée « à la main »,
    // triggers suspendus comme le ferait un script avorté — la bascule
    // refuse encore : l'état à deux clés référencé est INATTEIGNABLE.
    const rehashed = fingerprintUnder(after.fingerprint, 'H2', '+8801700000301');
    expect(rehashed).not.toBeNull();
    await owner.query('ALTER TABLE phone_claims DISABLE TRIGGER USER');
    await owner.query('UPDATE phone_claims SET phone_hmac = $2, hmac_key_id = $3 WHERE id = $1', [
      first,
      (rehashed as { value: string }).value,
      'H2',
    ]);
    await owner.query('ALTER TABLE phone_claims ENABLE TRIGGER USER');

    await expect(
      codeOf(() =>
        owner.query("UPDATE hmac_key_reference SET hmac_key_id = 'H2' WHERE singleton"),
      ),
    ).resolves.toBe(DB_ERROR.ROTATION_INCOMPLETE);

    const reference = firstRow(
      await owner.query<{ hmac_key_id: string }>(
        'SELECT hmac_key_id FROM hmac_key_reference WHERE singleton',
      ),
    );
    expect(reference.hmac_key_id).toBe('H1');
  });

  test('un trigger INCONNU sur la table → le script REFUSE avant toute écriture (jamais une suspension silencieuse)', async () => {
    await owner.query(
      `CREATE TRIGGER trg_test_inconnu BEFORE DELETE ON phone_claims
        FOR EACH ROW EXECUTE FUNCTION forbid_delete()`,
    );
    try {
      await expect(rotatePhoneHmacKey(owner, after)).rejects.toThrow(/trg_test_inconnu/);
      // Rien n'a bougé : la référence est toujours H1, les lignes intactes.
      const reference = firstRow(
        await owner.query<{ hmac_key_id: string }>(
          'SELECT hmac_key_id FROM hmac_key_reference WHERE singleton',
        ),
      );
      expect(reference.hmac_key_id).toBe('H1');
    } finally {
      await owner.query('DROP TRIGGER trg_test_inconnu ON phone_claims');
    }
  });

  test('LE SCRIPT : rotation réelle de bout en bout — re-hachage, intégrité, bascule, triggers réarmés', async () => {
    // État hérité du test précédent : une ligne déjà sous H2, une sous H1.
    const report = await rotatePhoneHmacKey(owner, after);
    expect(report.fromKeyId).toBe('H1');
    expect(report.toKeyId).toBe('H2');
    expect(report.rehashed).toBe(1); // celle qui restait sous H1

    // Le registre : TOUTES les ACTIVE sous H2 (compte de lignes, jamais un
    // agrégat seul), et chaque empreinte se RETROUVE sous la clé neuve.
    const claims = await owner.query<{ id: string; phone_hmac: string; hmac_key_id: string }>(
      "SELECT id, phone_hmac, hmac_key_id FROM phone_claims WHERE status = 'ACTIVE'",
    );
    expect(claims.rows).toHaveLength(2);
    for (const row of claims.rows) {
      expect(row.hmac_key_id).toBe('H2');
    }
    const expected = [
      fingerprintUnder(after.fingerprint, 'H2', '+8801700000301'),
      fingerprintUnder(after.fingerprint, 'H2', '+8801700000302'),
    ].map((f) => (f as { value: string }).value);
    expect(claims.rows.map((r) => r.phone_hmac).sort()).toEqual([...expected].sort());

    // La référence a basculé — EN DERNIER, sous le mur.
    const reference = firstRow(
      await owner.query<{ hmac_key_id: string }>(
        'SELECT hmac_key_id FROM hmac_key_reference WHERE singleton',
      ),
    );
    expect(reference.hmac_key_id).toBe('H2');

    // L'intégrité de bout en bout : le point unique re-dérive sous H2 et rend
    // l'adresse — empreinte et chiffré parlent toujours du même numéro.
    for (const row of claims.rows) {
      const resolution = await resolveVerifiedAddress(owner, after, row.id, true);
      expect(resolution.outcome).toBe('RESOLVED');
    }

    // LE FILET du DISABLE TRIGGER USER : tout est réarmé ('O' = ENABLED).
    const triggers = await owner.query<{ tgname: string; tgenabled: string }>(
      `SELECT tgname, tgenabled FROM pg_trigger
        WHERE tgrelid = 'phone_claims'::regclass AND NOT tgisinternal`,
    );
    expect(triggers.rows.length).toBeGreaterThan(0);
    for (const trigger of triggers.rows) {
      expect(trigger.tgenabled).toBe('O');
    }

    // Rejouer la rotation : rien à faire, zéro ligne touchée (idempotence).
    const replay = await rotatePhoneHmacKey(owner, after);
    expect(replay.rehashed).toBe(0);
  });

  test('après la bascule : déclarer sous l\'ANCIENNE clé refuse (P0109), la clé neuve passe', async () => {
    const accountId = await createAccount(app, nextIdentifier());
    const personId = firstRow(
      await app.query<{ person_id: string }>('SELECT person_id FROM accounts WHERE id = $1', [
        accountId,
      ]),
    ).person_id;
    const staleFp = fingerprintOf(before.fingerprint, '+8801700000303');
    await expect(
      codeOf(() =>
        owner.query(
          `INSERT INTO phone_claims (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
           VALUES ($1, $2, $3, $4, $5)`,
          [
            personId,
            staleFp.value,
            staleFp.hmacKeyId,
            encrypt(after.encryption, '+8801700000303'),
            after.encryption.activeKeyId,
          ],
        ),
      ),
    ).resolves.toBe(DB_ERROR.STALE_FINGERPRINT_KEY);

    const freshFp = fingerprintOf(after.fingerprint, '+8801700000303');
    await expect(
      owner.query(
        `INSERT INTO phone_claims (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, $5)`,
        [
          personId,
          freshFp.value,
          freshFp.hmacKeyId,
          encrypt(after.encryption, '+8801700000303'),
          after.encryption.activeKeyId,
        ],
      ),
    ).resolves.toBeDefined();
  });
});
