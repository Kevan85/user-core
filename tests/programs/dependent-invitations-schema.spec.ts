import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { encryptCivilIdentity, generateErasureSalt } from '../../src/crypto/person-identity';
import { dbErrorCode } from '../../src/db/errors';
import { buildPhoneColumns } from '../../src/phone/phone-columns';
import { createAccount } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// 021 — le rattachement porté par l'invitation : le clic (personne + droit +
// invitation, une transaction), l'idempotence par empreinte, l'acceptation
// qui crée les LIENS, la fenêtre TTL. Sous rôle bridé (les fonctions SONT le
// chemin) et sous owner quand un mur doit tenir au-delà des droits.
const crypto = assembleCryptoFromEnv({
  USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
  USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
  USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
  USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
});

const YEAR = new Date().getUTCFullYear();
const CAPS = { ttl: 3600, clientCap: 1000, clientWindow: 3600, lineCap: 1000, lineWindow: 3600 };

describe('021 — rattachement porté par l\'invitation (étape 2)', () => {
  let app: Pool;
  let owner: Pool;
  let minimumAge: number;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
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
    minimumAge = firstRow(
      await owner.query<{ age: number }>('SELECT emancipation_minimum_age() AS age'),
    ).age;
  });

  afterAll(async () => {
    await app.end();
    await owner.end();
  });

  function next(): number {
    seq += 1;
    return seq;
  }

  function personIdentifier(): string {
    return String(7_700_000_000 + next());
  }

  async function grantedProgram(code: string): Promise<string> {
    return firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO programs (code, label, access_mode) VALUES ($1, 'P', 'GRANTED') RETURNING id`,
      [code]),
    ).id;
  }

  interface ClickOptions {
    programId: string;
    phone: string;
    ref: string;
    birthYear?: number | null;
    identity?: boolean;
    clientCap?: number;
    lineCap?: number;
  }

  async function click(options: ClickOptions): Promise<{
    dependent_public_identifier: string | null;
    invitation_id: string | null;
    verdict: string;
  }> {
    const birthYear = options.birthYear === undefined ? YEAR - 8 : options.birthYear;
    const salt = generateErasureSalt();
    const withIdentity = options.identity !== false;
    const enc = withIdentity
      ? encryptCivilIdentity(crypto.encryption, salt, {
          nameComponents: ['Composante'],
          displayName: 'Ayant Droit De Test',
          birthDate: `${birthYear}-06-15`,
        })
      : null;
    const line = buildPhoneColumns(crypto, options.phone);
    return firstRow(
      await app.query(
        'SELECT * FROM open_dependent_access($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)',
        [
          options.programId,
          personIdentifier(),
          salt,
          enc?.token ?? null,
          enc?.encKeyId ?? null,
          withIdentity ? (enc?.birthYear ?? birthYear) : null,
          line.phoneHmac,
          line.hmacKeyId,
          `hmac-ref-${options.ref}`,
          'R1',
          CAPS.ttl,
          options.clientCap ?? CAPS.clientCap,
          CAPS.clientWindow,
          options.lineCap ?? CAPS.lineCap,
          CAPS.lineWindow,
        ],
      ),
    );
  }

  async function counts(): Promise<{ persons: number; grants: number; invitations: number; junctions: number }> {
    const row = firstRow(
      await owner.query<{ p: string; g: string; i: string; j: string }>(
        `SELECT (SELECT count(*) FROM persons) AS p,
                (SELECT count(*) FROM program_grants) AS g,
                (SELECT count(*) FROM program_invitations) AS i,
                (SELECT count(*) FROM program_invitation_dependents) AS j`,
      ),
    );
    return { persons: Number(row.p), grants: Number(row.g), invitations: Number(row.i), junctions: Number(row.j) };
  }

  /** Un compte dont la ligne est PROUVÉE (fixture owner, patron LOT 5). */
  async function accountWithProvenLine(phone: string): Promise<{ accountId: string; personId: string }> {
    const accountId = await createAccount(app, String(7_800_000_000 + next()));
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
    await owner.query(
      "UPDATE phone_claims SET status = 'ACTIVE', assurance_level = 'PROVEN' WHERE id = $1",
      [claimId],
    );
    return { accountId, personId };
  }

  async function accept(invitationId: string, accountId: string): Promise<string> {
    return firstRow(
      await app.query<{ accept_program_invitation: string }>(
        'SELECT accept_program_invitation($1, $2)',
        [invitationId, accountId],
      ),
    ).accept_program_invitation;
  }

  test('la jonction et le verrou : append-only, hors de portée du rôle applicatif', async () => {
    const programId = await grantedProgram('prog-murs');
    const done = await click({ programId, phone: '+243860000001', ref: 'murs-1' });
    expect(done.verdict).toBe('OPENED');

    // Le rôle applicatif n'écrit RIEN sur la jonction…
    await expect(
      app.query(
        `INSERT INTO program_invitation_dependents (invitation_id, dependent_person_id)
         SELECT $1, p.id FROM persons p LIMIT 1`,
        [done.invitation_id],
      ),
    ).rejects.toThrow(/permission denied/);
    await expect(
      app.query(`UPDATE program_invitation_dependents SET outcome = 'LINKED'`),
    ).rejects.toThrow(/permission denied/);
    // …et le verrou d'idempotence lui est INVISIBLE, pas même en lecture.
    await expect(app.query('SELECT * FROM program_idempotency_keys')).rejects.toThrow(
      /permission denied/,
    );

    // Sous owner : le contenu est immuable (P0101), outcome est set-once (P0104).
    const junction = firstRow(
      await owner.query<{ id: string }>(
        'SELECT id FROM program_invitation_dependents WHERE invitation_id = $1',
        [done.invitation_id],
      ),
    );
    await expect(
      owner
        .query(`UPDATE program_invitation_dependents SET dependent_person_id = gen_random_uuid() WHERE id = $1`, [junction.id])
        .catch((err: unknown) => Promise.reject(dbErrorCode(err))),
    ).rejects.toBe('P0101');
    await owner.query(`UPDATE program_invitation_dependents SET outcome = 'LINKED' WHERE id = $1`, [junction.id]);
    await expect(
      owner
        .query(`UPDATE program_invitation_dependents SET outcome = 'ALREADY_LINKED' WHERE id = $1`, [junction.id])
        .catch((err: unknown) => Promise.reject(dbErrorCode(err))),
    ).rejects.toBe('P0104');
    await expect(
      owner.query('DELETE FROM program_invitation_dependents WHERE id = $1', [junction.id]),
    ).rejects.toThrow(/suppression interdite/);
    await expect(
      owner.query('DELETE FROM program_idempotency_keys'),
    ).rejects.toThrow(/suppression interdite/);
  });

  test('le clic nominal : personne + droit PROGRAM + invitation + jonction — comptés, une transaction', async () => {
    const programId = await grantedProgram('prog-clic');
    const before = await counts();

    const done = await click({ programId, phone: '+243860000002', ref: 'clic-1' });
    expect(done.verdict).toBe('OPENED');
    expect(done.dependent_public_identifier).toMatch(/^[1-9][0-9]{9}$/);
    expect(done.invitation_id).not.toBeNull();

    const after = await counts();
    expect(after).toEqual({
      persons: before.persons + 1,
      grants: before.grants + 1,
      invitations: before.invitations + 1,
      junctions: before.junctions + 1,
    });

    const grant = firstRow(
      await owner.query<{ granted_by: string; status: string }>(
        `SELECT g.granted_by, g.status FROM program_grants g
          JOIN persons p ON p.id = g.person_id
         WHERE p.public_identifier = $1 AND g.program_id = $2`,
        [done.dependent_public_identifier, programId],
      ),
    );
    expect(grant).toEqual({ granted_by: 'PROGRAM', status: 'ACTIVE' });
  });

  test('les refus propres, et RIEN n\'est créé : SELF_SERVICE, adulte certain — la frontière d\'année passe (D-C)', async () => {
    const selfService = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO programs (code, label, access_mode) VALUES ('prog-libre', 'P', 'SELF_SERVICE') RETURNING id`,
      ),
    ).id;
    const programId = await grantedProgram('prog-refus');
    const before = await counts();

    expect((await click({ programId: selfService, phone: '+243860000003', ref: 'r-1' })).verdict).toBe('NOT_GRANTED_MODE');
    // L'adulte CERTAIN est refusé avec un verdict qui oriente (l'usager
    // adulte relève de l'ouverture sur personne connue, étape 3/4).
    expect((await click({ programId, phone: '+243860000003', ref: 'r-2', birthYear: YEAR - minimumAge - 1 })).verdict).toBe('OF_AGE');
    expect(await counts()).toEqual(before);

    // diff == seuil : peut-être mineur — le mur LAISSE (jamais plus dur, D-C).
    expect((await click({ programId, phone: '+243860000004', ref: 'r-3', birthYear: YEAR - minimumAge })).verdict).toBe('OPENED');

    // Sans identité : un ayant droit naît identifié (P0111).
    await expect(
      click({ programId, phone: '+243860000005', ref: 'r-4', identity: false }).catch(
        (err: unknown) => Promise.reject(dbErrorCode(err)),
      ),
    ).rejects.toBe('P0111');
  });

  test('IDEMPOTENCE (Q1) : re-clic de la même référence → même personne, zéro doublon', async () => {
    const programId = await grantedProgram('prog-idem');
    const first = await click({ programId, phone: '+243860000006', ref: 'idem-1' });
    expect(first.verdict).toBe('OPENED');
    const before = await counts();

    const replay = await click({ programId, phone: '+243860000006', ref: 'idem-1' });
    expect(replay.verdict).toBe('OPENED_EXISTING');
    expect(replay.dependent_public_identifier).toBe(first.dependent_public_identifier);
    expect(replay.invitation_id).toBe(first.invitation_id);
    // La deuxième fiche n'existe pas : aucun registre n'a bougé.
    expect(await counts()).toEqual(before);

    // La MÊME référence sous un AUTRE programme est un autre monde : le
    // verrou est par (programme, clé, empreinte) — aucune fuite transversale.
    const other = await grantedProgram('prog-idem-2');
    const crossed = await click({ programId: other, phone: '+243860000007', ref: 'idem-1' });
    expect(crossed.verdict).toBe('OPENED');
    expect(crossed.dependent_public_identifier).not.toBe(first.dependent_public_identifier);
  });

  test('plafond par CLIENT : refus FRANC et rien n\'est créé ; plafond par LIGNE : silencieux et le droit naît quand même', async () => {
    const programId = await grantedProgram('prog-caps');
    expect((await click({ programId, phone: '+243860000008', ref: 'cap-1' })).verdict).toBe('OPENED');
    const before = await counts();

    // Plafond client (1) déjà consommé : refus franc, AUCUNE naissance.
    expect((await click({ programId, phone: '+243860000009', ref: 'cap-2', clientCap: 1 })).verdict).toBe('REFUSED_CLIENT_CAP');
    expect(await counts()).toEqual(before);

    // Plafond de LIGNE : un AUTRE programme sonde la même ligne — l'invitation
    // naît supprimée (silence, 012), mais la personne ET son droit naissent :
    // le droit de l'ayant droit n'attend pas le parent (décision Kevin).
    const other = await grantedProgram('prog-caps-2');
    const muted = await click({ programId: other, phone: '+243860000008', ref: 'cap-3', lineCap: 1 });
    expect(muted.verdict).toBe('OPENED');
    const after = await counts();
    expect(after.persons).toBe(before.persons + 1);
    expect(after.grants).toBe(before.grants + 1);
    expect(
      firstRow(
        await owner.query<{ suppressed: boolean }>(
          'SELECT suppressed FROM program_invitations WHERE id = $1',
          [muted.invitation_id],
        ),
      ).suppressed,
    ).toBe(true);
  });

  test('l\'ACCEPTATION : les liens naissent (RESPONSIBLE), l\'acceptant ne reçoit AUCUN droit — compté', async () => {
    const programId = await grantedProgram('prog-accept');
    const phone = '+243860000010';
    // Deux clics, deux ayants droit, UNE invitation (idempotence par ligne).
    const one = await click({ programId, phone, ref: 'acc-1' });
    const two = await click({ programId, phone, ref: 'acc-2' });
    expect(two.invitation_id).toBe(one.invitation_id);

    const parent = await accountWithProvenLine(phone);
    expect(await accept(one.invitation_id as string, parent.accountId)).toBe('ACCEPTED');

    const links = firstRow(
      await owner.query<{ n: string }>(
        `SELECT count(*) AS n FROM person_responsibilities
          WHERE responsible_person_id = $1 AND status = 'ACTIVE' AND opened_by = 'RESPONSIBLE'`,
        [parent.personId],
      ),
    );
    expect(links.n).toBe('2');

    // L'absence de droit pour l'acceptant se prouve en COMPTANT.
    const parentGrants = firstRow(
      await owner.query<{ n: string }>(
        'SELECT count(*) AS n FROM program_grants WHERE person_id = $1',
        [parent.personId],
      ),
    );
    expect(parentGrants.n).toBe('0');

    const outcomes = await owner.query<{ outcome: string }>(
      'SELECT outcome FROM program_invitation_dependents WHERE invitation_id = $1',
      [one.invitation_id],
    );
    expect(outcomes.rows.map((r) => r.outcome)).toEqual(['LINKED', 'LINKED']);

    expect(
      firstRow(
        await owner.query<{ status: string }>(
          'SELECT status FROM program_invitations WHERE id = $1',
          [one.invitation_id],
        ),
      ).status,
    ).toBe('ACCEPTED');
  });

  test('un ayant droit devenu AUTONOME entre le clic et l\'acceptation est SAUTÉ avec trace — les autres sont liés quand même', async () => {
    const programId = await grantedProgram('prog-saut');
    const phone = '+243860000011';
    const kept = await click({ programId, phone, ref: 'saut-1' });
    const emancipated = await click({ programId, phone, ref: 'saut-2' });

    // La personne du deuxième clic devient autonome (compte actif, forgé par
    // LA porte de naissance, sous owner — le rôle applicatif ne le peut pas).
    const emancipatedPersonId = firstRow(
      await owner.query<{ id: string }>('SELECT id FROM persons WHERE public_identifier = $1', [
        emancipated.dependent_public_identifier,
      ]),
    ).id;
    await owner.query(
      `SELECT attach_account_to_person($1, $2, 'ACCOUNT_HOLDER',
        '$argon2id$v=19$m=65536,t=3,p=4$Zml4dHVyZQ$c2VjcmV0LWRlLWZpeHR1cmU', false, NULL)`,
      [emancipatedPersonId, String(7_900_000_000 + next())],
    );

    const parent = await accountWithProvenLine(phone);
    expect(await accept(kept.invitation_id as string, parent.accountId)).toBe('ACCEPTED');

    const outcomes = await owner.query<{ dependent_person_id: string; outcome: string }>(
      'SELECT dependent_person_id, outcome FROM program_invitation_dependents WHERE invitation_id = $1 ORDER BY created_at',
      [kept.invitation_id],
    );
    const byPerson = new Map(outcomes.rows.map((r) => [r.dependent_person_id, r.outcome]));
    expect(byPerson.get(emancipatedPersonId)).toBe('SKIPPED_AUTONOMOUS');
    // Le premier ayant droit, lui, est bien lié : le saut n'avorte rien.
    const links = firstRow(
      await owner.query<{ n: string }>(
        `SELECT count(*) AS n FROM person_responsibilities
          WHERE responsible_person_id = $1 AND status = 'ACTIVE'`,
        [parent.personId],
      ),
    );
    expect(links.n).toBe('1');
  });

  test('LA FENÊTRE (TTL) : expirée → inacceptable, aucun lien ; dans la fenêtre, le détenteur recyclé accepte (résidu déclaré)', async () => {
    const programId = await grantedProgram('prog-ttl');
    const phone = '+243860000012';
    const done = await click({ programId, phone, ref: 'ttl-1' });

    // Le détenteur RECYCLÉ de la ligne : il prouve la ligne (acte coûteux et
    // tracé — ici forgé), et DANS la fenêtre, il peut accepter. C'est le
    // résidu documenté de 021 : la possession est LA preuve (§6.5), la
    // fenêtre le borne, end_responsibility (staff) le répare.
    const stranger = await accountWithProvenLine(phone);
    expect(await accept(done.invitation_id as string, stranger.accountId)).toBe('ACCEPTED');
    const strangerLinks = firstRow(
      await owner.query<{ n: string }>(
        `SELECT count(*) AS n FROM person_responsibilities WHERE responsible_person_id = $1`,
        [stranger.personId],
      ),
    );
    expect(strangerLinks.n).toBe('1');

    // HORS fenêtre : une nouvelle invitation, expirée sous owner (DISABLE
    // TRIGGER borné — le contenu est immuable par trigger, y compris
    // expires_at ; réarmé aussitôt, le test C3 le vérifie à chaque run).
    const later = await click({ programId, phone: '+243860000013', ref: 'ttl-2' });
    // DISABLE TRIGGER USER exige son FILET (leçon C3) : le réarmement vit
    // dans un finally — un crash dans la fenêtre ne désarme pas la base.
    await owner.query('ALTER TABLE program_invitations DISABLE TRIGGER USER');
    try {
      await owner.query(
        `UPDATE program_invitations
            SET created_at = now() - interval '2 hours',
                expires_at = now() - interval '1 second'
          WHERE id = $1`,
        [later.invitation_id],
      );
    } finally {
      await owner.query('ALTER TABLE program_invitations ENABLE TRIGGER USER');
    }

    const other = await accountWithProvenLine('+243860000013');
    expect(await accept(later.invitation_id as string, other.accountId)).toBe('EXPIRED');
    const otherLinks = firstRow(
      await owner.query<{ n: string }>(
        `SELECT count(*) AS n FROM person_responsibilities WHERE responsible_person_id = $1`,
        [other.personId],
      ),
    );
    expect(otherLinks.n).toBe('0');
  });
});
