import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { AccountInvitationsService } from '../../src/invitations/account-invitations.service';
import { DependentAccessService } from '../../src/programs/dependent-access.service';
import { assembleReferenceKeyring } from '../../src/programs/reference-hmac';
import { buildPhoneColumns } from '../../src/phone/phone-columns';
import { createAccount } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// LE TEST QUI TRANCHE (étape 5) : l'identité d'un ayant droit invité ne sort
// QUE si les quatre conditions sont réunies — invitation PENDING, non
// supprimée, non expirée, ligne PROUVÉE de l'appelant. Chaque condition
// cassée rend ZÉRO ligne, et l'absence se prouve en COMPTANT — sous rôle
// bridé ET sous owner (la fonction porte le mur, pas les droits d'appel).
// Et quand tout est réuni : le NOM D'AFFICHAGE SEUL.
const crypto = assembleCryptoFromEnv({
  USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
  USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
  USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
  USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
});
const references = assembleReferenceKeyring({
  USER_CORE_REF_HMAC_KEYS: JSON.stringify({ R1: randomBytes(32).toString('base64') }),
  USER_CORE_REF_HMAC_ACTIVE_KEY_ID: 'R1',
});

const YEAR = new Date().getUTCFullYear();

describe('étape 5 — la divulgation minimale est un mur (022)', () => {
  let app: Pool;
  let owner: Pool;
  let click: DependentAccessService;
  let invitations: AccountInvitationsService;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    click = new DependentAccessService(app, crypto, references, {
      dependentInvitationTtlSeconds: 3600,
      inviteClientCap: 1000,
      inviteClientCapWindowSeconds: 3600,
      inviteLineCap: 1000,
      inviteLineCapWindowSeconds: 3600,
    });
    invitations = new AccountInvitationsService(app, crypto);
    await truncateTables(
      owner,
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

  async function grantedProgram(): Promise<string> {
    seq += 1;
    return firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO programs (code, label, access_mode) VALUES ($1, 'P', 'GRANTED') RETURNING id`,
        [`prog-mur-${seq}`],
      ),
    ).id;
  }

  async function accountWithProvenLine(phone: string): Promise<string> {
    seq += 1;
    const accountId = await createAccount(app, String(7_400_000_000 + seq));
    const personId = firstRow(
      await app.query<{ person_id: string }>('SELECT person_id FROM accounts WHERE id = $1', [accountId]),
    ).person_id;
    const line = buildPhoneColumns(crypto, phone);
    const claimId = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO phone_claims (person_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [personId, line.phoneHmac, line.hmacKeyId, line.phoneEncrypted, line.encKeyId],
      ),
    ).id;
    await owner.query("UPDATE phone_claims SET status = 'ACTIVE', assurance_level = 'PROVEN' WHERE id = $1", [claimId]);
    return accountId;
  }

  async function identityRowsCount(pool: Pool, invitationId: string, accountId: string): Promise<number> {
    const rows = await pool.query('SELECT * FROM read_invited_dependent_identities($1, $2)', [
      invitationId,
      accountId,
    ]);
    return rows.rowCount ?? 0;
  }

  test('les quatre conditions, COMPTÉES — chaque défaillance rend zéro ligne, sous rôle bridé ET sous owner', async () => {
    const programId = await grantedProgram();
    const phone = '+243840000001';
    const opened = await click.open(programId, 'mur-1', {
      nameComponents: ['Kabeya', 'Mwamba', 'Junior'],
      displayName: 'Kabeya Junior',
      birthDate: `${YEAR - 9}-06-15`,
    }, phone);
    if (opened.outcome !== 'ACCEPTED') throw new Error('ACCEPTED attendu');
    const invitationId = firstRow(
      await owner.query<{ id: string }>(
        `SELECT i.id FROM program_invitations i WHERE i.program_id = $1`,
        [programId],
      ),
    ).id;

    const rightAccount = await accountWithProvenLine(phone);
    const wrongAccount = await accountWithProvenLine('+243840000002');

    for (const pool of [app, owner]) {
      // Condition 4 cassée : ligne non prouvée pour CETTE invitation → rien.
      expect(await identityRowsCount(pool, invitationId, wrongAccount)).toBe(0);
      // Tout réuni → exactement UNE ligne (l'ayant droit du clic).
      expect(await identityRowsCount(pool, invitationId, rightAccount)).toBe(1);
    }

    // Condition 3 cassée : expirée (antidatée sous owner, filet C3 en finally).
    await owner.query('ALTER TABLE program_invitations DISABLE TRIGGER USER');
    try {
      await owner.query(
        `UPDATE program_invitations SET created_at = now() - interval '2 hours',
                expires_at = now() - interval '1 second' WHERE id = $1`,
        [invitationId],
      );
    } finally {
      await owner.query('ALTER TABLE program_invitations ENABLE TRIGGER USER');
    }
    for (const pool of [app, owner]) {
      expect(await identityRowsCount(pool, invitationId, rightAccount)).toBe(0);
    }

    // La liste du compte reflète le même mur : l'invitation expirée a disparu.
    expect(await invitations.list(rightAccount)).toEqual([]);
  });

  test('conditions 1 et 2 : une invitation close (déclinée) et une supprimée rendent zéro ligne', async () => {
    const programId = await grantedProgram();
    const phone = '+243840000003';
    const opened = await click.open(programId, 'mur-2', {
      nameComponents: ['Composante'],
      displayName: 'Ayant Droit',
      birthDate: `${YEAR - 8}-06-15`,
    }, phone);
    if (opened.outcome !== 'ACCEPTED') throw new Error('ACCEPTED attendu');
    const invitationId = firstRow(
      await owner.query<{ id: string }>('SELECT id FROM program_invitations WHERE program_id = $1', [programId]),
    ).id;
    const account = await accountWithProvenLine(phone);

    // Déclinée : la trace reste (§3.10), la lecture se ferme (condition 1).
    expect((await invitations.decline(account, invitationId)).outcome).toBe('DECLINED');
    for (const pool of [app, owner]) {
      expect(await identityRowsCount(pool, invitationId, account)).toBe(0);
    }

    // Supprimée (condition 2) : forgée sous owner avec sa jonction — même
    // son destinataire légitime ne voit rien (une invitation silencieuse
    // n'existe pas).
    const line = buildPhoneColumns(crypto, phone);
    const dependentId = firstRow(
      await owner.query<{ dependent_person_id: string }>(
        'SELECT dependent_person_id FROM program_invitation_dependents WHERE invitation_id = $1',
        [invitationId],
      ),
    ).dependent_person_id;
    const suppressedId = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO program_invitations (program_id, phone_hmac, hmac_key_id, suppressed, expires_at)
         VALUES ($1, $2, $3, true, now() + interval '1 hour') RETURNING id`,
        [programId, line.phoneHmac, line.hmacKeyId],
      ),
    ).id;
    await owner.query(
      `INSERT INTO program_invitation_dependents (invitation_id, dependent_person_id) VALUES ($1, $2)`,
      [suppressedId, dependentId],
    );
    for (const pool of [app, owner]) {
      expect(await identityRowsCount(pool, suppressedId, account)).toBe(0);
    }
    expect(await invitations.list(account)).toEqual([]);
  });

  test('tout réuni : le NOM D\'AFFICHAGE SEUL — les champs de la réponse sont comptés, et la colonne reste interdite en direct', async () => {
    const programId = await grantedProgram();
    const phone = '+243840000004';
    const one = await click.open(programId, 'mur-3a', {
      nameComponents: ['Kabeya', 'Mwamba', 'Junior'],
      displayName: 'Kabeya Junior',
      birthDate: `${YEAR - 9}-03-12`,
    }, phone);
    const two = await click.open(programId, 'mur-3b', {
      nameComponents: ['Kabeya', 'Ntumba', 'Grace'],
      displayName: 'Kabeya Grace',
      birthDate: `${YEAR - 7}-11-02`,
    }, phone);
    if (one.outcome !== 'ACCEPTED' || two.outcome !== 'ACCEPTED') throw new Error('ACCEPTED attendu');

    const account = await accountWithProvenLine(phone);
    const listed = await invitations.list(account);
    expect(listed).toHaveLength(1);
    const view = listed[0];
    if (view === undefined) throw new Error('une invitation attendue');

    // Les DEUX ayants droit, nom d'affichage seul — la FORME EXACTE est
    // l'assertion : toEqual échoue si un champ de plus (composantes, date,
    // identifiant) s'y glissait un jour.
    expect(view.dependents).toEqual([
      { displayName: 'Kabeya Junior' },
      { displayName: 'Kabeya Grace' },
    ]);

    // Et AUCUN chemin direct : la colonne du blob est hors du SELECT du rôle
    // applicatif (014) — le mur de 022 n'a pas de porte de service.
    await expect(app.query('SELECT civil_identity_encrypted FROM persons LIMIT 1')).rejects.toThrow(
      /permission denied/,
    );
    await expect(app.query('SELECT erasure_salt FROM persons LIMIT 1')).rejects.toThrow(
      /permission denied/,
    );

    // L'acceptation crée les liens (021) — le parcours ne change pas.
    expect((await invitations.accept(account, view.id)).outcome).toBe('ACCEPTED');
    const links = firstRow(
      await owner.query<{ n: string }>(
        `SELECT count(*) AS n FROM person_responsibilities r
          JOIN accounts a ON a.person_id = r.responsible_person_id
         WHERE a.id = $1 AND r.status = 'ACTIVE'`,
        [account],
      ),
    );
    expect(links.n).toBe('2');
  });
});
