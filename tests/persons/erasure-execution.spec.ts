import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { IdentityService } from '../../src/accounts/identity.service';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { encryptCivilIdentity, generateErasureSalt } from '../../src/crypto/person-identity';
import { DB_ERROR, dbErrorCode } from '../../src/db/errors';
import { AccountInvitationsService } from '../../src/invitations/account-invitations.service';
import { buildPhoneColumns } from '../../src/phone/phone-columns';
import { DependentAccessService } from '../../src/programs/dependent-access.service';
import { assembleReferenceKeyring } from '../../src/programs/reference-hmac';
import { createAccount } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';
import { fullKeyringEnv } from '../helpers/keyring-env';

// Étape 3 du LOT effacement : les PORTES (028) prouvées fermées hors
// effacement dû — sous owner, la forme exacte comprise — et le GESTE
// erase_person() prouvé complet : crypto-destruction (sel neuf ET blob NULL),
// neutralisation après révocation, profil éteint, compte désactivé (C4, la
// cascade 019 révoque les sessions), liens clos end_reason='ERASED' (C5),
// P0114 au COMMIT RÉEL si dernier responsable, et R3 : la liste montrée et
// la liste agie sont la même liste — compté en LIGNES, pas en noms.
const crypto = assembleCryptoFromEnv(fullKeyringEnv({
  USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
  USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
  USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
  USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
}));
const references = assembleReferenceKeyring(fullKeyringEnv({
  USER_CORE_REF_HMAC_KEYS: JSON.stringify({ R1: randomBytes(32).toString('base64') }),
  USER_CORE_REF_HMAC_ACTIVE_KEY_ID: 'R1',
}));

const YEAR = new Date().getUTCFullYear();
const TABLES = [
  'outbox',
  'person_erasures',
  'program_invitation_dependents',
  'program_idempotency_keys',
  'program_invitation_refusals',
  'program_invitations',
  'program_grants',
  'programs',
  'account_profiles',
  'phone_claims',
  'person_responsibilities',
  'accounts',
  'persons',
];

describe("effacement — les portes et le geste (028)", () => {
  let app: Pool;
  let owner: Pool;
  let identities: IdentityService;
  let invitations: AccountInvitationsService;
  let click: DependentAccessService;
  let seq = 0;
  let phoneSeq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    identities = new IdentityService(app, crypto);
    invitations = new AccountInvitationsService(app, crypto);
    click = new DependentAccessService(app, crypto, references, {
      dependentInvitationTtlSeconds: 3600,
      inviteClientCap: 1000,
      inviteClientCapWindowSeconds: 3600,
      inviteLineCap: 1000,
      inviteLineCapWindowSeconds: 3600,
    });
    await truncateTables(owner, ...TABLES);
  });

  afterAll(async () => {
    await truncateTables(owner, ...TABLES);
    await app.end();
    await owner.end();
  });

  function nextIdentifier(): string {
    seq += 1;
    return String(7_500_000_000 + seq);
  }

  function nextPhone(): string {
    phoneSeq += 1;
    return `+97000${String(100_000 + phoneSeq)}`;
  }

  async function codeOf(run: () => Promise<unknown>): Promise<string | undefined> {
    try {
      await run();
    } catch (err) {
      return dbErrorCode(err);
    }
    throw new Error("une violation était attendue : la garde n'a pas levé");
  }

  async function adult(): Promise<{ accountId: string; personId: string }> {
    const accountId = await createAccount(app, nextIdentifier());
    const personId = firstRow(
      await owner.query<{ person_id: string }>('SELECT person_id FROM accounts WHERE id = $1', [
        accountId,
      ]),
    ).person_id;
    return { accountId, personId };
  }

  async function attachMinor(responsibleAccountId: string): Promise<string> {
    const salt = generateErasureSalt();
    const enc = encryptCivilIdentity(crypto.encryption, salt, {
      nameComponents: ['Composante'],
      displayName: 'Personne De Test',
      birthDate: `${YEAR - 12}-06-15`,
    });
    return firstRow(
      await app.query<{ dependent_person_id: string }>(
        `SELECT dependent_person_id FROM attach_dependent($1, $2, $3, $4, $5, $6)`,
        [responsibleAccountId, nextIdentifier(), salt, enc.token, enc.encKeyId, enc.birthYear],
      ),
    ).dependent_person_id;
  }

  async function activeClaim(personId: string, phone: string): Promise<string> {
    const line = buildPhoneColumns(crypto, phone);
    const claimId = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO phone_claims (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [personId, line.phoneHmac, line.hmacKeyId, line.phoneEncrypted, line.encKeyId],
      ),
    ).id;
    await owner.query(
      `UPDATE phone_claims SET status = 'ACTIVE', assurance_level = 'PROVEN' WHERE id = $1`,
      [claimId],
    );
    return claimId;
  }

  async function requestSelf(accountId: string, mode: string): Promise<string> {
    const request = firstRow(
      await app.query<{ verdict: string; erasure_id: string | null }>(
        'SELECT * FROM request_erasure_self($1, $2)',
        [accountId, mode],
      ),
    );
    expect(request.verdict).toBe('REQUESTED');
    if (request.erasure_id === null) {
      throw new Error('REQUESTED sans identifiant de demande');
    }
    return request.erasure_id;
  }

  /** Demande due, posée par owner en CONTOURNANT les façades — pour prouver les murs seuls. */
  async function dueErasureBypassingFacade(personId: string): Promise<string> {
    return firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO person_erasures (person_id, mode, effective_after)
         VALUES ($1, 'IMMEDIATE', now()) RETURNING id`,
        [personId],
      ),
    ).id;
  }

  function freshSalt(): Buffer {
    return generateErasureSalt();
  }

  describe('les portes, prouvées fermées — les deux sens', () => {
    test('persons : la forme EXACTE de la destruction, sans effacement dû → P0101 (owner compris)', async () => {
      const { personId } = await adult();
      await expect(
        codeOf(() =>
          owner.query(
            `UPDATE persons SET erasure_salt = $2, civil_identity_encrypted = NULL, enc_key_id = NULL
              WHERE id = $1`,
            [personId, freshSalt()],
          ),
        ),
      ).resolves.toBe(DB_ERROR.IMMUTABLE);
    });

    test('persons : demande non due (DELAYED) → la porte reste fermée (P0101)', async () => {
      const { accountId, personId } = await adult();
      await requestSelf(accountId, 'DELAYED');
      await expect(
        codeOf(() =>
          owner.query(
            `UPDATE persons SET erasure_salt = $2, civil_identity_encrypted = NULL, enc_key_id = NULL
              WHERE id = $1`,
            [personId, freshSalt()],
          ),
        ),
      ).resolves.toBe(DB_ERROR.IMMUTABLE);
    });

    test('persons : effacement dû mais blob CONSERVÉ → la forme est refusée (P0101)', async () => {
      const { accountId, personId } = await adult();
      const result = await identities.provide(accountId, {
        nameComponents: ['Composante'],
        displayName: 'Personne De Test',
        birthDate: `${YEAR - 30}-06-15`,
      });
      expect(result.outcome).toBe('OK');
      await requestSelf(accountId, 'IMMEDIATE');

      await expect(
        codeOf(() =>
          owner.query(`UPDATE persons SET erasure_salt = $2 WHERE id = $1`, [
            personId,
            freshSalt(),
          ]),
        ),
      ).resolves.toBe(DB_ERROR.IMMUTABLE);
    });

    test('phone_claims : neutraliser une ACTIVE → P0101 ; une REVOKED sans effacement dû → P0101 aussi', async () => {
      const { accountId, personId } = await adult();
      const claimId = await activeClaim(personId, nextPhone());
      const neutralize = (pool: Pool) =>
        pool.query(
          `UPDATE phone_claims SET phone_hmac = 'ERASED:test', phone_encrypted = 'ERASED:test'
            WHERE id = $1`,
          [claimId],
        );

      await expect(codeOf(() => neutralize(owner))).resolves.toBe(DB_ERROR.IMMUTABLE);

      await owner.query(
        `UPDATE phone_claims SET status = 'REVOKED', revoke_reason = 'ADMIN' WHERE id = $1`,
        [claimId],
      );
      await expect(codeOf(() => neutralize(owner))).resolves.toBe(DB_ERROR.IMMUTABLE);

      // Et sous effacement dû, la porte s'ouvre — pour cette forme seule.
      await requestSelf(accountId, 'IMMEDIATE');
      await neutralize(owner);
      const row = firstRow(
        await owner.query<{ phone_hmac: string }>(
          'SELECT phone_hmac FROM phone_claims WHERE id = $1',
          [claimId],
        ),
      );
      expect(row.phone_hmac).toBe('ERASED:test');
    });

    test('mur 026 : COMPLETED avec une revendication VIVANTE est non représentable — les deux sens', async () => {
      const { accountId, personId } = await adult();
      const claimId = await activeClaim(personId, nextPhone());
      const erasureId = await requestSelf(accountId, 'IMMEDIATE');

      await expect(
        codeOf(() =>
          owner.query(`UPDATE person_erasures SET status = 'COMPLETED' WHERE id = $1`, [erasureId]),
        ),
      ).resolves.toBe(DB_ERROR.FORBIDDEN_TRANSITION);

      await owner.query(
        `UPDATE phone_claims SET status = 'REVOKED', revoke_reason = 'ADMIN' WHERE id = $1`,
        [claimId],
      );
      await owner.query(`UPDATE person_erasures SET status = 'COMPLETED' WHERE id = $1`, [
        erasureId,
      ]);
      const row = firstRow(
        await owner.query<{ status: string }>('SELECT status FROM person_erasures WHERE id = $1', [
          erasureId,
        ]),
      );
      expect(row.status).toBe('COMPLETED');
    });
  });

  describe('erase_person — les verdicts, idempotents pour le worker', () => {
    test('UNKNOWN · NOT_DUE · RETRACTED · ALREADY_COMPLETED', async () => {
      const ghost = firstRow(
        await app.query<{ verdict: string }>('SELECT * FROM erase_person($1)', [
          '00000000-0000-4000-8000-000000000000',
        ]),
      );
      expect(ghost.verdict).toBe('UNKNOWN');

      const delayed = await adult();
      const delayedId = await requestSelf(delayed.accountId, 'DELAYED');
      expect(
        firstRow(await app.query<{ verdict: string }>('SELECT * FROM erase_person($1)', [delayedId]))
          .verdict,
      ).toBe('NOT_DUE');

      await app.query('SELECT * FROM retract_erasure_self($1)', [delayed.accountId]);
      expect(
        firstRow(await app.query<{ verdict: string }>('SELECT * FROM erase_person($1)', [delayedId]))
          .verdict,
      ).toBe('RETRACTED');

      const done = await adult();
      const doneId = await requestSelf(done.accountId, 'IMMEDIATE');
      expect(
        firstRow(await app.query<{ verdict: string }>('SELECT * FROM erase_person($1)', [doneId]))
          .verdict,
      ).toBe('COMPLETED');
      expect(
        firstRow(await app.query<{ verdict: string }>('SELECT * FROM erase_person($1)', [doneId]))
          .verdict,
      ).toBe('ALREADY_COMPLETED');
    });
  });

  describe('erase_person — le geste complet', () => {
    test('crypto-destruction, neutralisation, profil, compte, sessions : tout, dans une transaction', async () => {
      const { accountId, personId } = await adult();
      const provided = await identities.provide(accountId, {
        nameComponents: ['Composante'],
        displayName: 'Personne De Test',
        birthDate: `${YEAR - 30}-06-15`,
      });
      expect(provided.outcome).toBe('OK');
      await app.query(
        `INSERT INTO account_profiles (account_id, display_name, locale) VALUES ($1, 'Nom Affiché', 'fr')`,
        [accountId],
      );
      const claimId = await activeClaim(personId, nextPhone());
      const sessionId = firstRow(
        await app.query<{ id: string }>(
          `INSERT INTO sessions (account_id, absolute_expires_at)
           VALUES ($1, now() + interval '1 day') RETURNING id`,
          [accountId],
        ),
      ).id;
      const before = firstRow(
        await owner.query<{ erasure_salt: Buffer; birth_year: number }>(
          'SELECT erasure_salt, birth_year FROM persons WHERE id = $1',
          [personId],
        ),
      );
      const claimBefore = firstRow(
        await owner.query<{ phone_hmac: string; phone_encrypted: string }>(
          'SELECT phone_hmac, phone_encrypted FROM phone_claims WHERE id = $1',
          [claimId],
        ),
      );

      const erasureId = await requestSelf(accountId, 'IMMEDIATE');
      const verdict = firstRow(
        await app.query<{ verdict: string }>('SELECT * FROM erase_person($1)', [erasureId]),
      );
      expect(verdict.verdict).toBe('COMPLETED');

      const person = firstRow(
        await owner.query<{
          erasure_salt: Buffer;
          civil_identity_encrypted: string | null;
          enc_key_id: string | null;
          birth_year: number;
        }>(
          `SELECT erasure_salt, civil_identity_encrypted, enc_key_id, birth_year
             FROM persons WHERE id = $1`,
          [personId],
        ),
      );
      expect(person.civil_identity_encrypted).toBeNull();
      expect(person.enc_key_id).toBeNull();
      expect(person.erasure_salt.equals(before.erasure_salt)).toBe(false); // sel NEUF
      expect(person.erasure_salt.length).toBe(32);
      expect(person.birth_year).toBe(before.birth_year); // résidu déclaré, intact

      const claim = firstRow(
        await owner.query<{
          status: string;
          revoke_reason: string;
          phone_hmac: string;
          phone_encrypted: string;
        }>(
          `SELECT status, revoke_reason, phone_hmac, phone_encrypted
             FROM phone_claims WHERE id = $1`,
          [claimId],
        ),
      );
      expect(claim.status).toBe('REVOKED');
      expect(claim.revoke_reason).toBe('ERASED');
      expect(claim.phone_hmac).not.toBe(claimBefore.phone_hmac);
      expect(claim.phone_encrypted).not.toBe(claimBefore.phone_encrypted);
      expect(claim.phone_hmac.startsWith('ERASED:')).toBe(true);

      const profile = firstRow(
        await owner.query<{ display_name: string | null; locale: string | null }>(
          'SELECT display_name, locale FROM account_profiles WHERE account_id = $1',
          [accountId],
        ),
      );
      expect(profile.display_name).toBeNull();
      expect(profile.locale).toBeNull();

      const account = firstRow(
        await owner.query<{ status: string }>('SELECT status FROM accounts WHERE id = $1', [
          accountId,
        ]),
      );
      expect(account.status).toBe('DEACTIVATED'); // C4, même transaction

      const session = firstRow(
        await owner.query<{ status: string }>('SELECT status FROM sessions WHERE id = $1', [
          sessionId,
        ]),
      );
      expect(session.status).toBe('REVOKED'); // cascade 019 : les sessions, rien d'autre

      const read = await identities.read(accountId);
      expect(read.outcome).toBe('ERASED');
      const address = firstRow(
        await app.query<{ token: string | null }>('SELECT read_phone_encrypted($1) AS token', [
          claimId,
        ]),
      );
      expect(address.token).toBeNull();
    });

    test('liens clos end_reason=ERASED (C5) — le co-responsable reste, P0114 satisfait', async () => {
      const responsible = await adult();
      const minorId = await attachMinor(responsible.accountId);
      const co = await adult();
      await app.query('SELECT * FROM open_responsibility_by_responsible($1, $2, $3)', [
        responsible.accountId,
        co.personId,
        minorId,
      ]);

      const erasureId = await requestSelf(responsible.accountId, 'IMMEDIATE');
      const verdict = firstRow(
        await app.query<{ verdict: string }>('SELECT * FROM erase_person($1)', [erasureId]),
      );
      expect(verdict.verdict).toBe('COMPLETED');

      const links = await owner.query<{ responsible_person_id: string; status: string; end_reason: string | null }>(
        `SELECT responsible_person_id, status, end_reason FROM person_responsibilities
          WHERE dependent_person_id = $1 ORDER BY seq`,
        [minorId],
      );
      expect(links.rowCount).toBe(2); // lignes ET contenu, jamais l'un sans l'autre
      const erased = links.rows.find((r) => r.responsible_person_id === responsible.personId);
      const kept = links.rows.find((r) => r.responsible_person_id === co.personId);
      expect(erased?.status).toBe('ENDED');
      expect(erased?.end_reason).toBe('ERASED');
      expect(kept?.status).toBe('ACTIVE');
    });

    test('dernier responsable, façade contournée : P0114 tranche au COMMIT RÉEL et rien n’est détruit', async () => {
      const responsible = await adult();
      await attachMinor(responsible.accountId);
      const erasureId = await dueErasureBypassingFacade(responsible.personId);

      // Une instruction, autocommit : le différé parle au commit.
      await expect(
        codeOf(() => app.query('SELECT * FROM erase_person($1)', [erasureId])),
      ).resolves.toBe(DB_ERROR.ORPHANED_DEPENDENT);

      const row = firstRow(
        await owner.query<{ status: string }>('SELECT status FROM person_erasures WHERE id = $1', [
          erasureId,
        ]),
      );
      expect(row.status).toBe('REQUESTED'); // la transaction entière est retombée
    });
  });

  describe('R3 — la liste montrée et la liste agie sont la même liste', () => {
    test('2 ayants droit dont 1 effacé : 1 nom affiché, 1 seul lien créé, la trace SKIPPED_ERASED posée', async () => {
      const programId = firstRow(
        await owner.query<{ id: string }>(
          `INSERT INTO programs (code, label, access_mode) VALUES ($1, 'P', 'GRANTED') RETURNING id`,
          [`prog-r3-${++seq}`],
        ),
      ).id;
      const phone = nextPhone();
      const dependent = (name: string) => ({
        nameComponents: [name],
        displayName: name,
        birthDate: `${YEAR - 9}-06-15`,
      });
      expect((await click.open(programId, `r3-a-${seq}`, dependent('Premier Enfant'), phone)).outcome).toBe('ACCEPTED');
      expect((await click.open(programId, `r3-b-${seq}`, dependent('Second Enfant'), phone)).outcome).toBe('ACCEPTED');

      const invitationId = firstRow(
        await owner.query<{ id: string }>(
          'SELECT id FROM program_invitations WHERE program_id = $1',
          [programId],
        ),
      ).id;
      const dependents = await owner.query<{ dependent_person_id: string }>(
        `SELECT dependent_person_id FROM program_invitation_dependents
          WHERE invitation_id = $1 ORDER BY created_at`,
        [invitationId],
      );
      expect(dependents.rowCount).toBe(2);
      const erasedDep = dependents.rows[0]?.dependent_person_id;
      const keptDep = dependents.rows[1]?.dependent_person_id;
      if (erasedDep === undefined || keptDep === undefined) {
        throw new Error('deux ayants droit étaient attendus');
      }

      // Le staff efface le premier (mineur, sans compte — chemin 026).
      const staff = await createAccount(app, nextIdentifier(), { role: 'PLATFORM_STAFF' });
      const request = firstRow(
        await app.query<{ verdict: string; erasure_id: string | null }>(
          'SELECT * FROM request_erasure_staff($1, $2)',
          [staff, erasedDep],
        ),
      );
      expect(request.verdict).toBe('REQUESTED');
      expect(
        firstRow(
          await app.query<{ verdict: string }>('SELECT * FROM erase_person($1)', [
            request.erasure_id,
          ]),
        ).verdict,
      ).toBe('COMPLETED');

      // Le parent : ligne prouvée, la liste MONTRE un seul nom.
      const parent = await adult();
      await activeClaim(parent.personId, phone);
      const views = await invitations.list(parent.accountId);
      expect(views).toHaveLength(1);
      expect(views[0]?.dependents).toHaveLength(1);
      expect(views[0]?.dependents[0]?.displayName).toBe('Second Enfant');

      // L'acceptation AGIT la même liste : un lien, pas deux — compté en lignes.
      const accepted = await invitations.accept(parent.accountId, invitationId);
      expect(accepted.outcome).toBe('ACCEPTED');

      const links = await owner.query(
        `SELECT id FROM person_responsibilities WHERE responsible_person_id = $1`,
        [parent.personId],
      );
      expect(links.rowCount).toBe(1);
      const outcomes = await owner.query<{ dependent_person_id: string; outcome: string }>(
        `SELECT dependent_person_id, outcome FROM program_invitation_dependents
          WHERE invitation_id = $1`,
        [invitationId],
      );
      expect(outcomes.rowCount).toBe(2);
      const skipped = outcomes.rows.find((r) => r.dependent_person_id === erasedDep);
      const linked = outcomes.rows.find((r) => r.dependent_person_id === keptDep);
      expect(skipped?.outcome).toBe('SKIPPED_ERASED');
      expect(linked?.outcome).toBe('LINKED');
    });
  });
});
