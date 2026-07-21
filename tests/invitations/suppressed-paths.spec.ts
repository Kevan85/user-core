import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { encryptCivilIdentity, generateErasureSalt } from '../../src/crypto/person-identity';
import { AccountInvitationsService } from '../../src/invitations/account-invitations.service';
import { buildPhoneColumns } from '../../src/phone/phone-columns';
import { createAccount } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// ÉTAPE 6, note 1 : « suppressed = UNKNOWN en lecture » — LE MOT « TOUS »
// EST LE MUR. Les chemins qui lisent program_invitations sont énumérés ici,
// et CHACUN est testé contre la même invitation supprimée, détenteur
// légitime de la ligne compris :
//   1. accept_program_invitation (012→021)      → UNKNOWN
//   2. decline_program_invitation (012→018)     → UNKNOWN
//   3. AccountInvitationsService.list           → absente
//   4. AccountInvitationsService.accept/decline → NOT_FOUND
//   5. read_invited_dependent_identities (022)  → zéro ligne
//   6. open_program_invitation (012, ré-appel)  → RECEIVED_EXISTING, même id
//      (indiscernable du chemin normal pour le programme)
// (grep de contrôle : aucun autre SELECT/JOIN de program_invitations ne vit
// dans src/ — vérifié au rapport de l'étape.)
//
// ÉTAPE 6, note 2 : L'EXTINCTION SILENCIEUSE (nommée en 021) — une
// supprimée qui expire ne produit RIEN, et l'absence se COMPTE.
const crypto = assembleCryptoFromEnv({
  USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
  USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
  USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
  USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
});

const YEAR = new Date().getUTCFullYear();
const CAPS = [3600, 1000, 3600, 1000, 3600] as const; // ttl, clientCap, clientWin, lineCap, lineWin

describe('étape 6 — suppressed est indiscernable d\'inexistante sur TOUS les chemins', () => {
  let app: Pool;
  let owner: Pool;
  let invitations: AccountInvitationsService;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    invitations = new AccountInvitationsService(app, crypto);
    await truncateTables(
      owner,
      'account_notifications',
      'outbox',
      'program_invitation_dependents',
      'program_idempotency_keys',
      'program_invitation_refusals',
      'program_invitations',
      'program_grants',
      'programs',
      'person_responsibilities',
      'phone_claims',
      'account_secrets',
      'accounts',
      'persons',
    );
  });

  afterAll(async () => {
    await app.end();
    await owner.end();
  });

  interface Fixture {
    programId: string;
    invitationId: string;
    accountId: string;
    phoneHmac: string;
    hmacKeyId: string;
  }

  /** Une invitation SUPPRIMÉE avec ayant droit, et le détenteur LÉGITIME de la ligne. */
  async function suppressedFixture(phone: string): Promise<Fixture> {
    seq += 1;
    const programId = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO programs (code, label, access_mode) VALUES ($1, 'P', 'GRANTED') RETURNING id`,
        [`prog-sup-${seq}`],
      ),
    ).id;
    const line = buildPhoneColumns(crypto, phone);

    const salt = generateErasureSalt();
    const enc = encryptCivilIdentity(crypto.encryption, salt, {
      nameComponents: ['Composante'],
      displayName: 'Jamais Vu',
      birthDate: `${YEAR - 8}-06-15`,
    });
    const dependentId = firstRow(
      await owner.query<{ id: string }>('SELECT create_person($1, $2, $3, $4, $5) AS id', [
        String(7_300_000_000 + seq),
        salt,
        enc.token,
        enc.encKeyId,
        enc.birthYear,
      ]),
    ).id;

    const invitationId = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO program_invitations (program_id, phone_hmac, hmac_key_id, suppressed, expires_at)
         VALUES ($1, $2, $3, true, now() + interval '1 hour') RETURNING id`,
        [programId, line.phoneHmac, line.hmacKeyId],
      ),
    ).id;
    await owner.query(
      'INSERT INTO program_invitation_dependents (invitation_id, dependent_person_id) VALUES ($1, $2)',
      [invitationId, dependentId],
    );

    const accountId = await createAccount(app, String(7_200_000_000 + seq));
    const personId = firstRow(
      await app.query<{ person_id: string }>('SELECT person_id FROM accounts WHERE id = $1', [accountId]),
    ).person_id;
    const claimId = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO phone_claims (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [personId, line.phoneHmac, line.hmacKeyId, line.phoneEncrypted, line.encKeyId],
      ),
    ).id;
    await owner.query("UPDATE phone_claims SET status = 'ACTIVE', assurance_level = 'PROVEN' WHERE id = $1", [claimId]);

    return { programId, invitationId, accountId, phoneHmac: line.phoneHmac, hmacKeyId: line.hmacKeyId };
  }

  test('les six chemins, énumérés et testés — même le détenteur légitime ne voit RIEN', async () => {
    const f = await suppressedFixture('+243830000001');

    // 1-2. Les fonctions de décision : UNKNOWN, sous rôle bridé ET owner.
    for (const pool of [app, owner]) {
      expect(
        firstRow(await pool.query<{ v: string }>('SELECT accept_program_invitation($1, $2) AS v', [f.invitationId, f.accountId])).v,
      ).toBe('UNKNOWN');
      expect(
        firstRow(await pool.query<{ v: string }>('SELECT decline_program_invitation($1, $2) AS v', [f.invitationId, f.accountId])).v,
      ).toBe('UNKNOWN');
    }

    // 3-4. Le service : liste vide, décisions NOT_FOUND.
    expect(await invitations.list(f.accountId)).toEqual([]);
    expect((await invitations.accept(f.accountId, f.invitationId)).outcome).toBe('NOT_FOUND');
    expect((await invitations.decline(f.accountId, f.invitationId)).outcome).toBe('NOT_FOUND');

    // 5. La lecture d'identité (022) : zéro ligne, compté.
    for (const pool of [app, owner]) {
      const rows = await pool.query('SELECT * FROM read_invited_dependent_identities($1, $2)', [f.invitationId, f.accountId]);
      expect(rows.rowCount).toBe(0);
    }

    // 6. Le ré-appel du programme : RECEIVED_EXISTING avec le MÊME id — pour
    // le programme, une supprimée est indiscernable d'une invitation vive.
    const reinvite = firstRow(
      await app.query<{ invitation_id: string; verdict: string }>(
        'SELECT * FROM open_program_invitation($1, $2, $3, $4, $5, $6, $7, $8)',
        [f.programId, f.phoneHmac, f.hmacKeyId, ...CAPS],
      ),
    );
    expect(reinvite.verdict).toBe('RECEIVED_EXISTING');
    expect(reinvite.invitation_id).toBe(f.invitationId);
  });

  test('L\'EXTINCTION SILENCIEUSE : une supprimée expirée rend UNKNOWN (jamais EXPIRED), meurt en silence, et l\'absence se COMPTE', async () => {
    const f = await suppressedFixture('+243830000002');

    // Elle expire (antidatée sous owner, filet C3 en finally).
    await owner.query('ALTER TABLE program_invitations DISABLE TRIGGER USER');
    try {
      await owner.query(
        `UPDATE program_invitations SET created_at = now() - interval '2 hours',
                expires_at = now() - interval '1 second' WHERE id = $1`,
        [f.invitationId],
      );
    } finally {
      await owner.query('ALTER TABLE program_invitations ENABLE TRIGGER USER');
    }

    const before = firstRow(
      await owner.query<{ o: string; n: string; r: string }>(
        `SELECT (SELECT count(*) FROM outbox) AS o,
                (SELECT count(*) FROM account_notifications) AS n,
                (SELECT count(*) FROM program_invitation_refusals) AS r`,
      ),
    );

    // L'ORDRE DES CONTRÔLES protège l'extinction : suppressed se teste AVANT
    // l'expiration — UNKNOWN, jamais EXPIRED (EXPIRED révélerait qu'elle a
    // existé). Sous rôle bridé ET owner.
    for (const pool of [app, owner]) {
      expect(
        firstRow(await pool.query<{ v: string }>('SELECT accept_program_invitation($1, $2) AS v', [f.invitationId, f.accountId])).v,
      ).toBe('UNKNOWN');
    }

    // Le ré-appel du programme la clôt paresseusement (EXPIRED, suppressed à
    // jamais) et une neuve naît — le cycle normal, rien de visible.
    const reinvite = firstRow(
      await app.query<{ invitation_id: string; verdict: string }>(
        'SELECT * FROM open_program_invitation($1, $2, $3, $4, $5, $6, $7, $8)',
        [f.programId, f.phoneHmac, f.hmacKeyId, ...CAPS],
      ),
    );
    expect(reinvite.invitation_id).not.toBe(f.invitationId);
    const extinct = firstRow(
      await owner.query<{ status: string; suppressed: boolean }>(
        'SELECT status, suppressed FROM program_invitations WHERE id = $1',
        [f.invitationId],
      ),
    );
    expect(extinct).toEqual({ status: 'EXPIRED', suppressed: true });

    // RIEN n'est sorti : outbox, notifications, journal des refus — les
    // TROIS compteurs sont inchangés (l'absence se prouve en comptant).
    const after = firstRow(
      await owner.query<{ o: string; n: string; r: string }>(
        `SELECT (SELECT count(*) FROM outbox) AS o,
                (SELECT count(*) FROM account_notifications) AS n,
                (SELECT count(*) FROM program_invitation_refusals) AS r`,
      ),
    );
    expect(after).toEqual(before);
  });
});
