import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { encrypt } from '../../src/crypto/aes-gcm';
import { fingerprintOf } from '../../src/crypto/fingerprint';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { AccountInvitationsService } from '../../src/invitations/account-invitations.service';
import { createAccount as createAccountFixture } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// Les invitations vues par le COMPTE, sous rôle bridé. La liste ne montre
// QUE la ligne prouvée du compte, jamais les suppressed, jamais les
// expirées ; accepter/décliner passent par les fonctions de 012 (BOLA en
// base) — le service traduit, il ne décide pas.
const crypto = assembleCryptoFromEnv({
  USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
  USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
  USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
  USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
});

describe('AccountInvitationsService', () => {
  let app: Pool;
  let owner: Pool;
  let invitations: AccountInvitationsService;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    invitations = new AccountInvitationsService(app);
  });

  beforeEach(async () => {
    await truncateTables(
      owner,
      'program_invitation_refusals',
      'program_invitations',
      'program_grants',
      'programs',
      'phone_claims',
      'accounts',
    );
  });

  afterAll(async () => {
    await app.end();
    await owner.end();
  });

  async function newProgram(code: string): Promise<string> {
    return firstRow(
      await owner.query<{ id: string }>(
        "INSERT INTO programs (code, label, access_mode) VALUES ($1, $1, 'GRANTED') RETURNING id",
        [code],
      ),
    ).id;
  }

  async function newAccount(): Promise<string> {
    seq += 1;
    return createAccountFixture(app, String(8500000000 + seq));
  }

  async function proveLine(accountId: string, phone: string): Promise<void> {
    const fp = fingerprintOf(crypto.fingerprint, phone);
    const claimId = firstRow(
      await app.query<{ id: string }>(
        `INSERT INTO phone_claims (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ((SELECT person_id FROM accounts WHERE id = $1), $2, $3, $4, 'E1') RETURNING id`,
        [accountId, fp.value, fp.hmacKeyId, encrypt(crypto.encryption, phone)],
      ),
    ).id;
    await owner.query(
      "UPDATE phone_claims SET status = 'ACTIVE', assurance_level = 'PROVEN' WHERE id = $1",
      [claimId],
    );
  }

  async function invite(
    programId: string,
    phone: string,
    caps: { lineCap?: number } = {},
  ): Promise<string> {
    const fp = fingerprintOf(crypto.fingerprint, phone);
    return firstRow(
      await app.query<{ invitation_id: string }>(
        'SELECT invitation_id FROM open_program_invitation($1, $2, $3, 3600, 100, 86400, $4, 86400)',
        [programId, fp.value, fp.hmacKeyId, caps.lineCap ?? 5],
      ),
    ).invitation_id;
  }

  test('la liste montre les invitations de MA ligne prouvée — et rien d\'autre', async () => {
    const line = '+243880000001';
    const holder = await newAccount();
    await proveLine(holder, line);

    const pVisible = await newProgram('prog-visible');
    const visibleId = await invite(pVisible, line);

    // Bruit qui ne doit PAS apparaître :
    const pOther = await newProgram('prog-autre-ligne');
    await invite(pOther, '+243880000002'); // une autre ligne
    const pExpired = await newProgram('prog-expiree');
    const fp = fingerprintOf(crypto.fingerprint, line);
    await owner.query(
      `INSERT INTO program_invitations (program_id, phone_hmac, hmac_key_id, expires_at, created_at)
       VALUES ($1, $2, $3, now() - interval '1 hour', now() - interval '2 hours')`,
      [pExpired, fp.value, fp.hmacKeyId],
    ); // expirée, sur MA ligne
    const pSettled = await newProgram('prog-close');
    const settledId = await invite(pSettled, line);
    await app.query('SELECT decline_program_invitation($1, $2)', [settledId, holder]);

    const view = await invitations.list(holder);
    expect(view).toHaveLength(1);
    expect(view[0]).toMatchObject({
      id: visibleId,
      programCode: 'prog-visible',
      programLabel: 'prog-visible',
    });
    expect(Object.keys(view[0]!).sort()).toEqual([
      'expiresAt',
      'id',
      'invitedAt',
      'programCode',
      'programLabel',
    ]);
  });

  test('une invitation SUPPRESSED (plafond de ligne) n\'apparaît JAMAIS dans la liste', async () => {
    const line = '+243880000010';
    const holder = await newAccount();
    await proveLine(holder, line);

    const p1 = await newProgram('prog-s1');
    const p2 = await newProgram('prog-s2');
    const p3 = await newProgram('prog-s3');
    await invite(p1, line, { lineCap: 2 });
    await invite(p2, line, { lineCap: 2 });
    await invite(p3, line, { lineCap: 2 }); // suppressed

    const view = await invitations.list(holder);
    expect(view).toHaveLength(2);
    expect(view.map((v) => v.programCode).sort()).toEqual(['prog-s1', 'prog-s2']);
  });

  test('un compte SANS ligne prouvée ne voit rien (déclarer ne suffit pas)', async () => {
    const line = '+243880000011';
    const programId = await newProgram('prog-rien');
    await invite(programId, line);

    const person = await newAccount();
    expect(await invitations.list(person)).toHaveLength(0);

    const fp = fingerprintOf(crypto.fingerprint, line);
    await app.query(
      `INSERT INTO phone_claims (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
       VALUES ((SELECT person_id FROM accounts WHERE id = $1), $2, $3, $4, 'E1')`,
      [person, fp.value, fp.hmacKeyId, encrypt(crypto.encryption, line)],
    );
    expect(await invitations.list(person)).toHaveLength(0); // PENDING ≠ prouvée
  });

  test('accepter → ACCEPTED, le droit naît ; re-accepter → ALREADY_SETTLED', async () => {
    const line = '+243880000012';
    const holder = await newAccount();
    await proveLine(holder, line);
    const programId = await newProgram('prog-accept');
    const invitationId = await invite(programId, line);

    expect(await invitations.accept(holder, invitationId)).toEqual({ outcome: 'ACCEPTED' });
    // Depuis 019 : le droit est né pour la PERSONNE du compte qui accepte.
    const grants = await owner.query<{ granted_by: string; status: string }>(
      `SELECT g.granted_by, g.status FROM program_grants g
        JOIN accounts a ON a.person_id = g.person_id WHERE a.id = $1`,
      [holder],
    );
    expect(grants.rows).toHaveLength(1);
    expect(grants.rows[0]).toEqual({ granted_by: 'PROGRAM', status: 'ACTIVE' });

    expect(await invitations.accept(holder, invitationId)).toEqual({
      outcome: 'ALREADY_SETTLED',
    });
  });

  test('décliner → DECLINED, aucun droit, et la liste se vide', async () => {
    const line = '+243880000013';
    const holder = await newAccount();
    await proveLine(holder, line);
    const programId = await newProgram('prog-decline');
    const invitationId = await invite(programId, line);

    expect(await invitations.decline(holder, invitationId)).toEqual({ outcome: 'DECLINED' });
    expect(await invitations.list(holder)).toHaveLength(0);
    const grants = firstRow(
      await owner.query<{ n: string }>('SELECT count(*) AS n FROM program_grants'),
    );
    expect(Number(grants.n)).toBe(0);
  });

  test('BOLA : un étranger (autre ligne prouvée) → NOT_FOUND, indiscernable de l\'inexistant', async () => {
    const programId = await newProgram('prog-bola');
    const invitationId = await invite(programId, '+243880000014');

    const stranger = await newAccount();
    await proveLine(stranger, '+243880000015');

    expect(await invitations.accept(stranger, invitationId)).toEqual({ outcome: 'NOT_FOUND' });
    expect(
      await invitations.accept(stranger, '00000000-0000-4000-8000-000000000000'),
    ).toEqual({ outcome: 'NOT_FOUND' });
    // Un id difforme n'est pas une erreur SQL : c'est un inconnu comme un autre.
    expect(await invitations.accept(stranger, 'pas-un-uuid')).toEqual({ outcome: 'NOT_FOUND' });
  });

  test('invitation expirée → EXPIRED au moment de la décision', async () => {
    const line = '+243880000016';
    const holder = await newAccount();
    await proveLine(holder, line);
    const programId = await newProgram('prog-exp');
    const fp = fingerprintOf(crypto.fingerprint, line);
    const staleId = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO program_invitations (program_id, phone_hmac, hmac_key_id, expires_at, created_at)
         VALUES ($1, $2, $3, now() - interval '1 minute', now() - interval '1 hour') RETURNING id`,
        [programId, fp.value, fp.hmacKeyId],
      ),
    ).id;
    expect(await invitations.accept(holder, staleId)).toEqual({ outcome: 'EXPIRED' });
  });
});
