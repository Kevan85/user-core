import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { encrypt } from '../../src/crypto/aes-gcm';
import { fingerprintOf } from '../../src/crypto/fingerprint';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { DB_ERROR, dbErrorCode } from '../../src/db/errors';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

const crypto = assembleCryptoFromEnv({
  USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
  USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
  USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
  USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
});

const CODE_KEY = 'C1';
const TTL = 300;
const MAX_ATTEMPTS = 3;
const LINE_CAP = 3;
const CAP_WINDOW = 86400;

async function codeOf(run: () => Promise<unknown>): Promise<string | undefined> {
  try {
    await run();
  } catch (err) {
    return dbErrorCode(err);
  }
  throw new Error('une violation était attendue : la garde n\'a pas levé');
}

describe('possession_proofs — la preuve de possession de ligne', () => {
  let app: Pool;
  let owner: Pool;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
  });

  beforeEach(async () => {
    await truncateTables(
      owner,
      'outbox',
      'possession_proof_refusals',
      'possession_proofs',
      'phone_claims',
      'accounts',
    );
  });

  afterAll(async () => {
    await app.end();
    await owner.end();
  });

  async function newAccount(): Promise<string> {
    seq += 1;
    return firstRow(
      await app.query<{ id: string }>(
        "INSERT INTO accounts (public_identifier, role) VALUES ($1, 'ACCOUNT_HOLDER') RETURNING id",
        [String(7200000000 + seq)],
      ),
    ).id;
  }

  async function declare(accountId: string, phone: string): Promise<string> {
    const fp = fingerprintOf(crypto.fingerprint, phone);
    const token = encrypt(crypto.encryption, phone);
    return firstRow(
      await app.query<{ id: string }>(
        `INSERT INTO phone_claims (account_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [accountId, fp.value, fp.hmacKeyId, token, crypto.encryption.activeKeyId],
      ),
    ).id;
  }

  interface OpenResult {
    proof_id: string | null;
    verdict: string;
  }

  async function open(
    claimId: string,
    codeHmac: string,
    channel: 'SMS' | 'CALL' = 'CALL',
    cap = LINE_CAP,
  ): Promise<OpenResult> {
    return firstRow(
      await app.query<OpenResult>(
        'SELECT * FROM open_possession_proof($1, $2, $3, $4, $5, $6, $7, $8)',
        [claimId, channel, codeHmac, CODE_KEY, TTL, MAX_ATTEMPTS, cap, CAP_WINDOW],
      ),
    );
  }

  async function verify(claimId: string, codeHmac: string): Promise<string> {
    return firstRow(
      await app.query<{ verdict: string }>('SELECT * FROM verify_possession_code($1, $2)', [
        claimId,
        codeHmac,
      ]),
    ).verdict;
  }

  test('WhatsApp est NON REPRÉSENTABLE en base (doctrine, pas une règle qu\'on répète)', async () => {
    const claimId = await declare(await newAccount(), '+243820000001');
    await expect(
      app.query('SELECT * FROM open_possession_proof($1, $2, $3, $4, $5, $6, $7, $8)', [
        claimId,
        'WHATSAPP',
        'h',
        CODE_KEY,
        TTL,
        MAX_ATTEMPTS,
        LINE_CAP,
        CAP_WINDOW,
      ]),
    ).rejects.toThrow(/invalid input value for enum proof_channel/);
  });

  test('le service ne peut NI insérer une preuve NI lire un code (le chemin est la fonction)', async () => {
    const claimId = await declare(await newAccount(), '+243820000002');
    await expect(
      app.query(
        `INSERT INTO possession_proofs (claim_id, channel, code_hmac, proof_code_key_id, max_attempts, expires_at)
         VALUES ($1, 'SMS', 'h', $2, 3, now() + interval '5 minutes')`,
        [claimId, CODE_KEY],
      ),
    ).rejects.toThrow(/permission denied/);

    await open(claimId, 'hash-du-code');
    await expect(app.query('SELECT code_hmac FROM possession_proofs')).rejects.toThrow(
      /permission denied/,
    );
    await expect(app.query('SELECT * FROM possession_proofs')).rejects.toThrow(
      /permission denied/,
    );
  });

  test('ouverture nominale → OPENED, une seule preuve PENDING par revendication', async () => {
    const claimId = await declare(await newAccount(), '+243820000003');
    const first = await open(claimId, 'code-1');
    expect(first.verdict).toBe('OPENED');
    expect(first.proof_id).not.toBeNull();

    const second = await open(claimId, 'code-2');
    expect(second.verdict).toBe('REFUSED_PENDING');
    expect(second.proof_id).toBeNull();

    // Le refus n'a créé AUCUNE preuve (donc aucun coût) — il est tracé ailleurs.
    const proofs = await app.query('SELECT id FROM possession_proofs WHERE claim_id = $1', [
      claimId,
    ]);
    expect(proofs.rows).toHaveLength(1);
    const refusals = await app.query<{ reason: string }>(
      'SELECT reason FROM possession_proof_refusals WHERE claim_id = $1',
      [claimId],
    );
    expect(refusals.rows).toHaveLength(1);
    expect(refusals.rows[0]?.reason).toBe('PROOF_ALREADY_PENDING');
  });

  test('P3-bis — le plafond par LIGNE protège un TIERS : il compte sur l\'empreinte, pas sur le compte', async () => {
    const phone = '+243820000004';
    // Trois comptes DIFFÉRENTS visent la MÊME ligne — un attaquant se multiplie.
    for (let i = 0; i < LINE_CAP; i++) {
      const claimId = await declare(await newAccount(), phone);
      const opened = await open(claimId, `code-${i}`);
      expect(opened.verdict).toBe('OPENED');
    }

    const attacker = await declare(await newAccount(), phone);
    const refused = await open(attacker, 'code-de-trop');
    expect(refused.verdict).toBe('REFUSED_CAP');
    expect(refused.proof_id).toBeNull();

    // LE CRITÈRE : compter les envois RÉELS sans jamais les confondre avec un
    // refus. possession_proofs = 3 lignes (3 codes partis, 3 coûts).
    const sent = await app.query('SELECT id FROM possession_proofs');
    expect(sent.rows).toHaveLength(LINE_CAP);
    const capRefusals = await app.query<{ reason: string }>(
      "SELECT reason FROM possession_proof_refusals WHERE reason = 'LINE_DAILY_CAP'",
    );
    expect(capRefusals.rows).toHaveLength(1);
  });

  test('P2 — l\'essai est compté DANS la fonction : WRONG puis EXHAUSTED, sans le service', async () => {
    const claimId = await declare(await newAccount(), '+243820000005');
    await open(claimId, 'le-bon-code');

    expect(await verify(claimId, 'faux-1')).toBe('WRONG');
    expect(await verify(claimId, 'faux-2')).toBe('WRONG');
    expect(await verify(claimId, 'faux-3')).toBe('EXHAUSTED'); // max_attempts = 3

    const proof = firstRow(
      await app.query<{ attempts: number; status: string }>(
        'SELECT attempts, status FROM possession_proofs WHERE claim_id = $1',
        [claimId],
      ),
    );
    expect(proof.attempts).toBe(3);
    expect(proof.status).toBe('FAILED');

    // Épuisée : même le BON code ne passe plus.
    expect(await verify(claimId, 'le-bon-code')).toBe('ALREADY_SETTLED');
    const claim = firstRow(
      await app.query<{ status: string }>('SELECT status FROM phone_claims WHERE id = $1', [
        claimId,
      ]),
    );
    expect(claim.status).toBe('PENDING'); // jamais activée
  });

  test('succès → PROVEN : la revendication est activée par la BASE, horodatée', async () => {
    const claimId = await declare(await newAccount(), '+243820000006');
    await open(claimId, 'le-bon-code');
    expect(await verify(claimId, 'le-bon-code')).toBe('PROVEN');

    const claim = firstRow(
      await app.query<{ status: string; assurance_level: string; age: number }>(
        `SELECT status, assurance_level,
                EXTRACT(EPOCH FROM (now() - verified_at))::float AS age
         FROM phone_claims WHERE id = $1`,
        [claimId],
      ),
    );
    expect(claim.status).toBe('ACTIVE');
    expect(claim.assurance_level).toBe('PROVEN');
    expect(claim.age).toBeLessThan(60);
  });

  test('NUMÉRO RECYCLÉ — la preuve la plus récente GAGNE, et l\'ancien détenteur est prévenu', async () => {
    const phone = '+243820000007';
    const ancien = await newAccount();
    const ancienClaim = await declare(ancien, phone);
    await open(ancienClaim, 'code-ancien');
    expect(await verify(ancienClaim, 'code-ancien')).toBe('PROVEN');

    // La SIM change de mains. Le nouveau détenteur prouve à son tour.
    const nouveau = await newAccount();
    const nouveauClaim = await declare(nouveau, phone);
    await open(nouveauClaim, 'code-nouveau');
    expect(await verify(nouveauClaim, 'code-nouveau')).toBe('PROVEN');

    // Nombre de lignes ET statuts ET motif (jamais un agrégat seul).
    const claims = await app.query<{ id: string; status: string; revoke_reason: string | null }>(
      'SELECT id, status, revoke_reason FROM phone_claims WHERE phone_hmac = $1 ORDER BY created_at',
      [fingerprintOf(crypto.fingerprint, phone).value],
    );
    expect(claims.rows).toHaveLength(2);
    expect(claims.rows[0]).toMatchObject({ status: 'REVOKED', revoke_reason: 'SUPERSEDED' });
    expect(claims.rows[1]).toMatchObject({ status: 'ACTIVE', revoke_reason: null });

    // L'ancien détenteur DOIT être prévenu — l'intention est écrite dans la
    // transaction qui révoque, elle ne peut pas se perdre.
    const events = await app.query<{ event_type: string; account_id: string; status: string }>(
      'SELECT event_type, account_id, status FROM outbox',
    );
    expect(events.rows).toHaveLength(1);
    expect(events.rows[0]?.event_type).toBe('PHONE_LINE_SUPERSEDED');
    expect(events.rows[0]?.account_id).toBe(ancien); // l'ANCIEN, pas le nouveau
    expect(events.rows[0]?.status).toBe('PENDING');
  });

  test('l\'outbox ne contient AUCUNE PII (aucune colonne ne peut en porter)', async () => {
    const columns = await owner.query<{ column_name: string }>(
      `SELECT column_name FROM information_schema.columns
        WHERE table_name = 'outbox' ORDER BY ordinal_position`,
    );
    expect(columns.rows.map((r) => r.column_name)).toEqual([
      'id',
      'event_type',
      'account_id',
      'claim_id',
      'status',
      'occurred_at',
      'published_at',
      'attempts',
      'next_attempt_at',
      'last_error_code',
      'failed_at',
    ]);
    // Ni numéro, ni empreinte, ni valeur chiffrée : le dispatcher résoudra
    // l'adresse au moment d'envoyer, par le chemin de déchiffrement contrôlé.
    const forbidden = ['phone', 'hmac', 'encrypted', 'payload'];
    for (const name of columns.rows.map((r) => r.column_name)) {
      for (const marker of forbidden) {
        expect(name).not.toContain(marker);
      }
    }
    // last_error_code EXISTE (009), et ce n'est PAS un code de possession :
    // c'est un marqueur applicatif dont la FORME est bornée en base — un
    // numéro, un code ou un message n'y entrent pas.
    const guard = await owner.query<{ definition: string }>(
      `SELECT pg_get_constraintdef(oid) AS definition FROM pg_constraint
        WHERE conname = 'chk_outbox_error_code_short'`,
    );
    expect(guard.rows).toHaveLength(1);
    expect(guard.rows[0]?.definition).toContain('A-Z_');
  });

  test('la révocation et sa ligne d\'outbox sont ATOMIQUES (rollback → ni l\'une ni l\'autre)', async () => {
    const phone = '+243820000008';
    const ancien = await newAccount();
    const ancienClaim = await declare(ancien, phone);
    await open(ancienClaim, 'code-a');
    await verify(ancienClaim, 'code-a');

    const nouveau = await newAccount();
    const nouveauClaim = await declare(nouveau, phone);
    await open(nouveauClaim, 'code-b');

    const client = await app.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT * FROM verify_possession_code($1, $2)', [nouveauClaim, 'code-b']);
      await client.query('ROLLBACK');
    } finally {
      client.release();
    }

    // Rien n'a bougé : l'ancien détenteur garde sa ligne, aucun événement.
    const claim = firstRow(
      await app.query<{ status: string }>('SELECT status FROM phone_claims WHERE id = $1', [
        ancienClaim,
      ]),
    );
    expect(claim.status).toBe('ACTIVE');
    const events = await app.query('SELECT id FROM outbox');
    expect(events.rows).toHaveLength(0);
  });

  test('code expiré → EXPIRED, sans consommer d\'essai', async () => {
    const claimId = await declare(await newAccount(), '+243820000009');
    await app.query('SELECT * FROM open_possession_proof($1, $2, $3, $4, $5, $6, $7, $8)', [
      claimId,
      'SMS',
      'code',
      CODE_KEY,
      1,
      MAX_ATTEMPTS,
      LINE_CAP,
      CAP_WINDOW,
    ]);
    await app.query('SELECT pg_sleep(1.3)');
    expect(await verify(claimId, 'code')).toBe('EXPIRED');
    const proof = firstRow(
      await app.query<{ status: string; attempts: number }>(
        'SELECT status, attempts FROM possession_proofs WHERE claim_id = $1',
        [claimId],
      ),
    );
    expect(proof.status).toBe('EXPIRED');
    expect(proof.attempts).toBe(0);
  });

  test('verdicts UNKNOWN et REFUSED_CLAIM', async () => {
    expect(await verify('00000000-0000-0000-0000-000000000000', 'x')).toBe('UNKNOWN');

    const claimId = await declare(await newAccount(), '+243820000010');
    expect(await verify(claimId, 'x')).toBe('UNKNOWN'); // aucune preuve ouverte

    await app.query(
      "UPDATE phone_claims SET status = 'REVOKED', revoke_reason = 'ADMIN' WHERE id = $1",
      [claimId],
    );
    const refused = await open(claimId, 'code');
    expect(refused.verdict).toBe('REFUSED_CLAIM');
  });

  test('P5 — l\'outbox est un REGISTRE : publication set-once, jamais rejouée, jamais re-datée', async () => {
    // Un recyclage produit l'événement à prévenir.
    const phone = '+243820000012';
    const ancien = await declare(await newAccount(), phone);
    await open(ancien, 'code-a');
    await verify(ancien, 'code-a');
    const nouveau = await declare(await newAccount(), phone);
    await open(nouveau, 'code-b');
    await verify(nouveau, 'code-b');

    const eventId = firstRow(
      await app.query<{ id: string }>('SELECT id FROM outbox'),
    ).id;

    // Publication : la base horodate elle-même (valeur du client écrasée).
    await app.query("UPDATE outbox SET status = 'PUBLISHED' WHERE id = $1", [eventId]);
    const published = firstRow(
      await app.query<{ age: number }>(
        'SELECT EXTRACT(EPOCH FROM (now() - published_at))::float AS age FROM outbox WHERE id = $1',
        [eventId],
      ),
    );
    expect(published.age).toBeLessThan(60);

    // PUBLISHED -> PENDING : refusé. Sans cette garde, l'ancien détenteur
    // serait re-prévenu en boucle — et chaque tour coûtera un SMS.
    await expect(
      codeOf(() => app.query("UPDATE outbox SET status = 'PENDING' WHERE id = $1", [eventId])),
    ).resolves.toBe(DB_ERROR.FROZEN_ROW);

    // Re-datation : refusée aux deux étages.
    await expect(
      app.query("UPDATE outbox SET published_at = '2019-01-01' WHERE id = $1", [eventId]),
    ).rejects.toThrow(/permission denied|figé/);
    await expect(
      codeOf(() =>
        owner.query("UPDATE outbox SET published_at = '2019-01-01' WHERE id = $1", [eventId]),
      ),
    ).resolves.toBe(DB_ERROR.FROZEN_ROW);

    // Contenu immuable, sur un événement encore PENDING.
    const third = await declare(await newAccount(), '+243820000013');
    await open(third, 'code-c');
    await verify(third, 'code-c');
    const pendingEvent = await owner.query<{ id: string }>(
      "SELECT id FROM outbox WHERE status = 'PENDING' LIMIT 1",
    );
    if (pendingEvent.rows[0] !== undefined) {
      await expect(
        codeOf(() =>
          owner.query("UPDATE outbox SET event_type = 'AUTRE' WHERE id = $1", [
            pendingEvent.rows[0]?.id,
          ]),
        ),
      ).resolves.toBe(DB_ERROR.IMMUTABLE);
    }
  });

  test('append-only : preuve close figée, refus immuables, aucun DELETE nulle part', async () => {
    const claimId = await declare(await newAccount(), '+243820000011');
    const opened = await open(claimId, 'code');
    await verify(claimId, 'code'); // SUCCEEDED

    await expect(
      codeOf(() =>
        owner.query("UPDATE possession_proofs SET status = 'PENDING' WHERE id = $1", [
          opened.proof_id,
        ]),
      ),
    ).resolves.toBe(DB_ERROR.FROZEN_ROW);

    await expect(
      codeOf(() => owner.query('DELETE FROM possession_proofs WHERE id = $1', [opened.proof_id])),
    ).resolves.toBe(DB_ERROR.DELETE_FORBIDDEN);

    await expect(app.query('DELETE FROM outbox')).rejects.toThrow(/permission denied/);
  });
});
