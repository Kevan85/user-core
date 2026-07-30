import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { IdentityService } from '../../src/accounts/identity.service';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { AccountInvitationsService } from '../../src/invitations/account-invitations.service';
import { buildPhoneColumns } from '../../src/phone/phone-columns';
import { resolveVerifiedAddress } from '../../src/phone/verified-address';
import { DependentAccessService } from '../../src/programs/dependent-access.service';
import { assembleReferenceKeyring } from '../../src/programs/reference-hmac';
import { createAccount } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';
import { fullKeyringEnv } from '../helpers/keyring-env';

// Étape 2 du LOT effacement : « effacé » est un ÉTAT que la base DÉCLARE
// (027) — jamais une conclusion tirée d'un échec de déchiffrement. Les deux
// lectures d'identité rendent `erased`, les deux lectures d'adresse rendent
// NULL. L'ESPION prouve les deux faces : ZÉRO trace INTÉGRITÉ sur lecture
// d'une effacée, AU MOINS UNE sur une vraie corruption — le canal reste
// vivant, pas seulement silencieux.
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
  'phone_claims',
  'person_responsibilities',
  'accounts',
  'persons',
];

describe('effacement — les chemins de lecture déclarent (027)', () => {
  let app: Pool;
  let owner: Pool;
  let identities: IdentityService;
  let invitations: AccountInvitationsService;
  let click: DependentAccessService;
  let integritySpy: jest.SpyInstance;
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

  beforeEach(() => {
    integritySpy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
  });

  afterEach(() => {
    integritySpy.mockRestore();
  });

  function integrityCalls(): number {
    return integritySpy.mock.calls.filter((args) => String(args[0]).includes('INTÉGRITÉ')).length;
  }

  function nextIdentifier(): string {
    seq += 1;
    return String(7_600_000_000 + seq);
  }

  function nextPhone(): string {
    phoneSeq += 1;
    return `+98000${String(100_000 + phoneSeq)}`;
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

  /** IMMEDIATE (due à l'instant) puis COMPLETED — la personne est effacée. */
  async function eraseSelf(accountId: string): Promise<void> {
    const request = firstRow(
      await app.query<{ verdict: string; erasure_id: string | null }>(
        `SELECT * FROM request_erasure_self($1, 'IMMEDIATE')`,
        [accountId],
      ),
    );
    expect(request.verdict).toBe('REQUESTED');
    await owner.query(`UPDATE person_erasures SET status = 'COMPLETED' WHERE id = $1`, [
      request.erasure_id,
    ]);
  }

  /** Effacement STAFF d'une personne sans compte (le mineur invité). */
  async function eraseByStaff(personId: string): Promise<void> {
    const staff = await createAccount(app, nextIdentifier(), { role: 'PLATFORM_STAFF' });
    const request = firstRow(
      await app.query<{ verdict: string; erasure_id: string | null }>(
        'SELECT * FROM request_erasure_staff($1, $2)',
        [staff, personId],
      ),
    );
    expect(request.verdict).toBe('REQUESTED');
    await owner.query(`UPDATE person_erasures SET status = 'COMPLETED' WHERE id = $1`, [
      request.erasure_id,
    ]);
  }

  async function provideIdentity(accountId: string): Promise<void> {
    const result = await identities.provide(accountId, {
      nameComponents: ['Composante'],
      displayName: 'Personne De Test',
      birthDate: `${YEAR - 30}-06-15`,
    });
    expect(result.outcome).toBe('OK');
  }

  /** Revendication ACTIVE prouvée — posée AVANT tout effacement (mur 026). */
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

  describe('read_person_identity — la base déclare', () => {
    test('erased : false avant, true après COMPLETED — lu sous rôle bridé', async () => {
      const { accountId, personId } = await adult();
      const before = firstRow(
        await app.query<{ erased: boolean }>('SELECT erased FROM read_person_identity($1)', [
          personId,
        ]),
      );
      expect(before.erased).toBe(false);

      await eraseSelf(accountId);
      const after = firstRow(
        await app.query<{ erased: boolean }>('SELECT erased FROM read_person_identity($1)', [
          personId,
        ]),
      );
      expect(after.erased).toBe(true);
    });
  });

  describe('IdentityService — ERASED distinct, et AVANT NOT_PROVIDED (C6)', () => {
    test('effacée SANS blob : ERASED, jamais NOT_PROVIDED — l’ordre est le test', async () => {
      const { accountId } = await adult(); // née sans identité : blob NULL
      await eraseSelf(accountId);
      const result = await identities.read(accountId);
      expect(result.outcome).toBe('ERASED');
    });

    test('effacée AVEC blob : ERASED sans un mot sur le canal d’intégrité', async () => {
      const { accountId } = await adult();
      await provideIdentity(accountId);
      await eraseSelf(accountId);

      const result = await identities.read(accountId);
      expect(result.outcome).toBe('ERASED');
      expect(integrityCalls()).toBe(0); // l'absence se prouve en comptant les appels
    });

    test('provide() sur une effacée : verdict ERASED propre — le mur P0116 reste la base', async () => {
      const { accountId, personId } = await adult();
      await eraseSelf(accountId);

      const result = await identities.provide(accountId, {
        nameComponents: ['Revenant'],
        displayName: 'Revenant',
        birthDate: `${YEAR - 30}-06-15`,
      });
      expect(result.outcome).toBe('ERASED');
      const row = firstRow(
        await owner.query<{ empty: boolean }>(
          'SELECT civil_identity_encrypted IS NULL AS empty FROM persons WHERE id = $1',
          [personId],
        ),
      );
      expect(row.empty).toBe(true); // rien n'a été écrit
    });

    test('le canal d’intégrité reste VIVANT : une vraie corruption crie encore', async () => {
      const { accountId, personId } = await adult();
      await provideIdentity(accountId);
      // Corruption réelle du registre (owner) : blob illisible, personne NON effacée.
      await owner.query(
        `UPDATE persons SET civil_identity_encrypted = 'corrompu' WHERE id = $1`,
        [personId],
      );

      const result = await identities.read(accountId);
      expect(result.outcome).toBe('INTEGRITY_VIOLATION');
      expect(integrityCalls()).toBeGreaterThanOrEqual(1);
    });
  });

  describe('read_invited_dependent_identities — l’ayant droit invité effacé', () => {
    test('la ligne se déclare erased ; le service la saute sans bruit d’intégrité', async () => {
      const programId = firstRow(
        await owner.query<{ id: string }>(
          `INSERT INTO programs (code, label, access_mode) VALUES ($1, 'P', 'GRANTED') RETURNING id`,
          [`prog-effacement-${++seq}`],
        ),
      ).id;
      const phone = nextPhone();
      const opened = await click.open(
        programId,
        `ref-effacement-${seq}`,
        {
          nameComponents: ['Composante'],
          displayName: 'Personne De Test',
          birthDate: `${YEAR - 9}-06-15`,
        },
        phone,
      );
      expect(opened.outcome).toBe('ACCEPTED');
      const invitationId = firstRow(
        await owner.query<{ id: string }>(
          'SELECT id FROM program_invitations WHERE program_id = $1',
          [programId],
        ),
      ).id;
      const dependentId = firstRow(
        await owner.query<{ dependent_person_id: string }>(
          'SELECT dependent_person_id FROM program_invitation_dependents WHERE invitation_id = $1',
          [invitationId],
        ),
      ).dependent_person_id;

      // Le responsable pressenti, ligne PROUVÉE : les quatre conditions de 022 tiennent.
      const accepting = await adult();
      await activeClaim(accepting.personId, phone);

      const before = firstRow(
        await app.query<{ erased: boolean }>(
          'SELECT erased FROM read_invited_dependent_identities($1, $2)',
          [invitationId, accepting.accountId],
        ),
      );
      expect(before.erased).toBe(false);

      await eraseByStaff(dependentId);

      const after = firstRow(
        await app.query<{ erased: boolean }>(
          'SELECT erased FROM read_invited_dependent_identities($1, $2)',
          [invitationId, accepting.accountId],
        ),
      );
      expect(after.erased).toBe(true);

      const views = await invitations.list(accepting.accountId);
      expect(views).toHaveLength(1);
      expect(views[0]?.dependents).toHaveLength(0); // plus de nom à afficher
      expect(integrityCalls()).toBe(0);
    });
  });

  describe('les lectures d’adresse se taisent — le complément à la raison (c)', () => {
    test('read_phone_encrypted et resolve_notification_address : NULL pour une effacée, même sur une revendication ACTIVE', async () => {
      const { accountId, personId } = await adult();
      const claimId = await activeClaim(personId, nextPhone());

      const alive = firstRow(
        await app.query<{ direct: string | null; active: string | null }>(
          'SELECT read_phone_encrypted($1) AS direct, resolve_notification_address($1) AS active',
          [claimId],
        ),
      );
      expect(alive.direct).not.toBeNull();
      expect(alive.active).not.toBeNull();

      await eraseSelf(accountId);
      const silent = firstRow(
        await app.query<{ direct: string | null; active: string | null }>(
          'SELECT read_phone_encrypted($1) AS direct, resolve_notification_address($1) AS active',
          [claimId],
        ),
      );
      expect(silent.direct).toBeNull();
      expect(silent.active).toBeNull();
    });

    test('resolveVerifiedAddress (requireActive=false, le chemin découvert) : NO_ADDRESS, et la parade P4 ne crie pas', async () => {
      const { accountId, personId } = await adult();
      const claimId = await activeClaim(personId, nextPhone());
      await eraseSelf(accountId);

      const resolution = await resolveVerifiedAddress(app, crypto, claimId, false);
      expect(resolution.outcome).toBe('NO_ADDRESS');
      expect(integrityCalls()).toBe(0);
    });
  });
});
