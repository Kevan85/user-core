import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { CountingDispatcher } from '../../src/dispatch/simulator/counting-dispatcher';
import { encrypt } from '../../src/crypto/aes-gcm';
import { fingerprintOf } from '../../src/crypto/fingerprint';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { generateErasureSalt } from '../../src/crypto/person-identity';
import { OutboxPublisher } from '../../src/outbox/publisher';
import { assembleProofCodeKeyring, hashProofCode } from '../../src/proving/proof-code';
import { createAccount } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// C1 — « la preuve la plus récente gagne » dans LES DEUX SENS (008… non :
// CDC §6.5 + §3.4). Le sens ① (le supersédé a un compte) marchait déjà ;
// le sens ② (le supersédé est une personne SANS compte — émancipation
// entamée, jamais achevée) ABORTAIT avant 018 : l'outbox exigeait un compte.
// Le refus « ce numéro est déjà pris » revenait par la porte de derrière,
// en violation de contrainte brute. Ces tests prouvent que la reprise
// RÉUSSIT, que rien ne part vers la ligne reprise, et que le silence est
// TRACÉ.
const crypto = assembleCryptoFromEnv({
  USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
  USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
  USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
  USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
});
const codeKeyring = assembleProofCodeKeyring({
  USER_CORE_PROOF_CODE_KEYS: JSON.stringify({ C1: randomBytes(32).toString('base64') }),
  USER_CORE_PROOF_CODE_ACTIVE_KEY_ID: 'C1',
});

describe('C1 — reprise de ligne : les deux sens, avec et sans compte', () => {
  let app: Pool;
  let owner: Pool;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    await truncateTables(
      owner,
      'account_notifications',
      'outbox',
      'possession_proofs',
      'phone_claims',
      'accounts',
      'persons',
    );
  });

  afterAll(async () => {
    await truncateTables(
      owner,
      'account_notifications',
      'outbox',
      'possession_proofs',
      'phone_claims',
      'accounts',
      'persons',
    );
    await app.end();
    await owner.end();
  });

  function nextIdentifier(): string {
    seq += 1;
    return String(8_700_000_000 + seq);
  }

  async function adultPerson(): Promise<{ accountId: string; personId: string }> {
    const accountId = await createAccount(app, nextIdentifier());
    const personId = firstRow(
      await app.query<{ person_id: string }>('SELECT person_id FROM accounts WHERE id = $1', [
        accountId,
      ]),
    ).person_id;
    return { accountId, personId };
  }

  /** Une personne SANS compte — le profil de l'émancipation entamée. */
  async function personWithoutAccount(): Promise<string> {
    return firstRow(
      await owner.query<{ id: string }>('SELECT create_person($1, $2, NULL, NULL, NULL) AS id', [
        nextIdentifier(),
        generateErasureSalt(),
      ]),
    ).id;
  }

  async function declareClaim(personId: string, phone: string): Promise<string> {
    const fp = fingerprintOf(crypto.fingerprint, phone);
    return firstRow(
      await app.query<{ id: string }>(
        `INSERT INTO phone_claims (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [personId, fp.value, fp.hmacKeyId, encrypt(crypto.encryption, phone), crypto.encryption.activeKeyId],
      ),
    ).id;
  }

  async function activateUnderOwner(claimId: string): Promise<void> {
    await owner.query(
      "UPDATE phone_claims SET status = 'ACTIVE', assurance_level = 'PROVEN' WHERE id = $1",
      [claimId],
    );
  }

  /** Prouver la ligne par LE chemin réel : preuve ouverte puis code vérifié. */
  async function proveByCode(claimId: string): Promise<string> {
    const hashed = hashProofCode(codeKeyring, '123456');
    const opened = firstRow(
      await app.query<{ proof_id: string | null; verdict: string }>(
        'SELECT * FROM open_possession_proof($1, $2, $3, $4, 300, 3, 10, 86400)',
        [claimId, 'SMS', hashed.hmac, hashed.keyId],
      ),
    );
    expect(opened.verdict).toBe('OPENED');
    return firstRow(
      await app.query<{ verdict: string }>('SELECT * FROM verify_possession_code($1, $2)', [
        claimId,
        hashed.hmac,
      ]),
    ).verdict;
  }

  function publisher(dispatcher: CountingDispatcher): OutboxPublisher {
    return new OutboxPublisher(app, dispatcher, crypto, {
      batchSize: 20,
      leaseSeconds: 1,
      maxAttempts: 5,
      backoffBaseSeconds: 1,
      backoffCapSeconds: 1,
    });
  }

  test('① le supersédé A un compte : reprise, révocation SUPERSEDED, notification DÉPOSÉE dans son compte, zéro envoi externe', async () => {
    const holder = await adultPerson();
    const line = '+880170000000001';
    const holderClaim = await declareClaim(holder.personId, line);
    await activateUnderOwner(holderClaim);

    const newcomer = await adultPerson();
    const newcomerClaim = await declareClaim(newcomer.personId, line);
    await expect(proveByCode(newcomerClaim)).resolves.toBe('PROVEN');

    const superseded = firstRow(
      await app.query<{ status: string; revoke_reason: string }>(
        'SELECT status, revoke_reason FROM phone_claims WHERE id = $1',
        [holderClaim],
      ),
    );
    expect(superseded).toEqual({ status: 'REVOKED', revoke_reason: 'SUPERSEDED' });

    // Drainage : l'ancien détenteur est prévenu DANS SON COMPTE — jamais sur
    // la ligne reprise (elle est dans la main de quelqu'un d'autre).
    const dispatcher = new CountingDispatcher();
    const report = await publisher(dispatcher).drain();
    expect(report.published).toBe(1);
    expect(dispatcher.sent).toHaveLength(0); // l'ABSENCE se prouve en comptant

    const notified = firstRow(
      await owner.query<{ n: string }>(
        `SELECT count(*) AS n FROM account_notifications
          WHERE account_id = $1 AND event_type = 'PHONE_LINE_SUPERSEDED'`,
        [holder.accountId],
      ),
    );
    expect(notified.n).toBe('1');
  });

  test('② le supersédé n’a PAS de compte : la reprise RÉUSSIT (le test qui manquait), zéro message externe, le silence est TRACÉ', async () => {
    // Le profil exact de l'émancipation entamée : une personne, une ligne
    // ACTIVE, aucun compte. Avant 018 : outbox.account_id NOT NULL → la
    // transaction de la MÈRE qui reprenait SA SIM abortait.
    const orphanHolder = await personWithoutAccount();
    const line = '+880170000000002';
    const orphanClaim = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO phone_claims (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [
          orphanHolder,
          fingerprintOf(crypto.fingerprint, line).value,
          fingerprintOf(crypto.fingerprint, line).hmacKeyId,
          encrypt(crypto.encryption, line),
          crypto.encryption.activeKeyId,
        ],
      ),
    ).id;
    await activateUnderOwner(orphanClaim);

    // La mère reprend SA ligne — par le chemin réel, sous rôle bridé.
    const mother = await adultPerson();
    const motherClaim = await declareClaim(mother.personId, line);
    await expect(proveByCode(motherClaim)).resolves.toBe('PROVEN'); // ✅ plus d'abort

    const superseded = firstRow(
      await app.query<{ status: string; revoke_reason: string }>(
        'SELECT status, revoke_reason FROM phone_claims WHERE id = $1',
        [orphanClaim],
      ),
    );
    expect(superseded).toEqual({ status: 'REVOKED', revoke_reason: 'SUPERSEDED' });

    // Drainage : AUCUN canal — pas de compte, pas de ligne (reprise). On ne
    // notifie pas, on TRACE, et l'événement reste re-tentable (la personne
    // peut achever son émancipation demain).
    const dispatcher = new CountingDispatcher();
    const report = await publisher(dispatcher).drain();
    expect(dispatcher.sent).toHaveLength(0);
    expect(report.notNotifiable).toBe(1);
    expect(report.retried).toBe(1);

    const traced = firstRow(
      await owner.query<{ attempts: number; last_error_code: string; status: string }>(
        `SELECT attempts, last_error_code, status FROM outbox WHERE person_id = $1`,
        [orphanHolder],
      ),
    );
    expect(traced).toEqual({ attempts: 1, last_error_code: 'NOT_NOTIFIABLE', status: 'PENDING' });
  });
});
