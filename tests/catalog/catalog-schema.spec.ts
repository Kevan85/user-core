import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { encryptCivilIdentity, generateErasureSalt } from '../../src/crypto/person-identity';
import { DB_ERROR, dbErrorCode } from '../../src/db/errors';
import { createAccount as createAccountFixture } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// Invariants de 008 (transposés à la PERSONNE par 019), sous rôle bridé ET
// sous owner. Le catalogue est un DROIT D'ACCÈS : activé / désactivé,
// historisé, jamais un facturier — et depuis 019, il appartient à la
// PERSONNE (« Scolaria pour Junior », jamais « la famille a Scolaria »).
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

describe('catalogue — invariants en base', () => {
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
      'program_grants',
      'programs',
      'person_responsibilities',
      'accounts',
      'persons',
    );
  });

  afterAll(async () => {
    await app.end();
    await owner.end();
  });

  async function newAccount(): Promise<string> {
    seq += 1;
    // Depuis 011, le chemin unique — les fixtures l'empruntent comme le service.
    return createAccountFixture(app, String(7600000000 + seq));
  }

  // Le programme est une DONNÉE : on l'ajoute par un INSERT (acte
  // d'administration, sous owner), jamais par une migration.
  async function newProgram(code: string): Promise<string> {
    return firstRow(
      await owner.query<{ id: string }>(
        'INSERT INTO programs (code, label, access_mode) VALUES ($1, $2, $3) RETURNING id',
        [code, `Programme ${code}`, 'SELF_SERVICE'],
      ),
    ).id;
  }

  // Depuis 019 : le droit appartient à la PERSONNE — le compte y mène.
  async function personOf(accountId: string): Promise<string> {
    return firstRow(
      await app.query<{ person_id: string }>('SELECT person_id FROM accounts WHERE id = $1', [
        accountId,
      ]),
    ).person_id;
  }

  async function grant(accountId: string, programId: string): Promise<string> {
    return grantToPerson(await personOf(accountId), programId);
  }

  async function grantToPerson(personId: string, programId: string): Promise<string> {
    return firstRow(
      await app.query<{ id: string }>(
        "INSERT INTO program_grants (person_id, program_id, granted_by) VALUES ($1, $2, 'SELF') RETURNING id",
        [personId, programId],
      ),
    ).id;
  }

  async function grantsOf(
    personId: string,
  ): Promise<{ status: string; revoke_reason: string | null }[]> {
    const rows = await app.query<{ status: string; revoke_reason: string | null }>(
      'SELECT status, revoke_reason FROM program_grants WHERE person_id = $1 ORDER BY granted_at',
      [personId],
    );
    return rows.rows;
  }

  test('le code d\'un programme est une DONNÉE : ajouter un programme est un INSERT', async () => {
    const id = await newProgram('alpha');
    const row = firstRow(
      await app.query<{ code: string; status: string }>(
        'SELECT code, status FROM programs WHERE id = $1',
        [id],
      ),
    );
    expect(row.code).toBe('alpha');
    expect(row.status).toBe('ACTIVE');
    // Un deuxième programme s'ajoute sans toucher au schéma.
    await expect(newProgram('beta-2')).resolves.toBeDefined();
  });

  test('forme du code imposée ; doublon refusé', async () => {
    await newProgram('gamma');
    await expect(newProgram('gamma')).rejects.toThrow(/uq_programs_code/);
    await expect(newProgram('AVEC-MAJUSCULES')).rejects.toThrow(/chk_programs_code_shape/);
    await expect(newProgram('a')).rejects.toThrow(/chk_programs_code_shape/);
  });

  test('le service ne peut PAS créer, modifier ni supprimer un programme (acte d\'administration)', async () => {
    const id = await newProgram('delta');
    await expect(
      app.query("INSERT INTO programs (code, label, access_mode) VALUES ('pirate', 'x', 'SELF_SERVICE')"),
    ).rejects.toThrow(/permission denied/);
    await expect(
      app.query("UPDATE programs SET code = 'autre' WHERE id = $1", [id]),
    ).rejects.toThrow(/permission denied/);
    await expect(app.query('DELETE FROM programs WHERE id = $1', [id])).rejects.toThrow(
      /permission denied/,
    );
  });

  test('un droit ACTIVE unique par (personne, programme)', async () => {
    const accountId = await newAccount();
    const programId = await newProgram('epsilon');
    await grant(accountId, programId);
    await expect(grant(accountId, programId)).rejects.toThrow(/uq_program_grants_active/);
  });

  test('APPEND-ONLY — désactiver puis réactiver : DEUX lignes, l\'histoire reste lisible', async () => {
    const accountId = await newAccount();
    const programId = await newProgram('zeta');
    const first = await grant(accountId, programId);

    await app.query(
      "UPDATE program_grants SET status = 'REVOKED', revoke_reason = 'SELF' WHERE id = $1",
      [first],
    );
    const second = await grant(accountId, programId); // réactiver = ligne NEUVE
    expect(second).not.toBe(first);

    const rows = await grantsOf(await personOf(accountId));
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({ status: 'REVOKED', revoke_reason: 'SELF' });
    expect(rows[1]).toMatchObject({ status: 'ACTIVE', revoke_reason: null });
  });

  test('la révocation est horodatée par la BASE ; sans motif → refus ; ligne révoquée figée', async () => {
    const accountId = await newAccount();
    const programId = await newProgram('eta');
    const id = await grant(accountId, programId);

    await expect(
      codeOf(() => app.query("UPDATE program_grants SET status = 'REVOKED' WHERE id = $1", [id])),
    ).resolves.toBe(DB_ERROR.FORBIDDEN_TRANSITION);

    await app.query(
      "UPDATE program_grants SET status = 'REVOKED', revoke_reason = 'SELF' WHERE id = $1",
      [id],
    );
    const row = firstRow(
      await app.query<{ age: number }>(
        'SELECT EXTRACT(EPOCH FROM (now() - revoked_at))::float AS age FROM program_grants WHERE id = $1',
        [id],
      ),
    );
    expect(row.age).toBeLessThan(60);

    await expect(
      codeOf(() => app.query("UPDATE program_grants SET status = 'ACTIVE' WHERE id = $1", [id])),
    ).resolves.toBe(DB_ERROR.FROZEN_ROW);
    await expect(
      codeOf(() =>
        owner.query("UPDATE program_grants SET revoked_at = '2019-01-01' WHERE id = $1", [id]),
      ),
    ).resolves.toBe(DB_ERROR.FROZEN_ROW);
  });

  test('contenu immuable : on ne « déplace » pas un droit d\'une personne à une autre', async () => {
    const accountId = await newAccount();
    const other = await newAccount();
    const otherPerson = await personOf(other);
    const programId = await newProgram('theta');
    const id = await grant(accountId, programId);
    await expect(
      codeOf(() =>
        owner.query('UPDATE program_grants SET person_id = $2 WHERE id = $1', [id, otherPerson]),
      ),
    ).resolves.toBe(DB_ERROR.IMMUTABLE);
  });

  test('019 : un droit peut naître pour une personne SANS compte actif — le mineur est le cas nominal ; un programme retiré, lui, refuse toujours', async () => {
    // L'ancienne garde « aucun droit sous un compte désactivé » est tombée
    // avec 019, délibérément : le droit appartient à la personne, et une
    // personne sans compte (mineur) ou au compte mort en porte.
    const accountId = await newAccount();
    const programId = await newProgram('iota');
    await app.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [accountId]);
    await expect(grant(accountId, programId)).resolves.toBeDefined();

    // Une personne sans AUCUN compte (le profil du mineur rattaché).
    seq += 1;
    const bare = firstRow(
      await owner.query<{ id: string }>('SELECT create_person($1, $2, NULL, NULL, NULL) AS id', [
        String(7_650_000_000 + seq),
        generateErasureSalt(),
      ]),
    ).id;
    await expect(grantToPerson(bare, programId)).resolves.toBeDefined();

    const live = await newAccount();
    const retired = await newProgram('kappa');
    await owner.query(
      "UPDATE programs SET status = 'RETIRED', retired_at = now() WHERE id = $1",
      [retired],
    );
    await expect(codeOf(() => grant(live, retired))).resolves.toBe(DB_ERROR.DEAD_PARENT);
  });

  test('un droit DÉJÀ accordé survit au retrait du programme (on ne coupe pas une famille)', async () => {
    const accountId = await newAccount();
    const programId = await newProgram('lambda');
    await grant(accountId, programId);
    await owner.query(
      "UPDATE programs SET status = 'RETIRED', retired_at = now() WHERE id = $1",
      [programId],
    );
    const rows = await grantsOf(await personOf(accountId));
    expect(rows).toHaveLength(1);
    expect(rows[0]?.status).toBe('ACTIVE');
  });

  test('C13 FINAL (019) — compte désactivé : les SESSIONS tombent, les DROITS restent (ils sont à la personne)', async () => {
    const accountId = await newAccount();
    const alpha = await newProgram('mu-un');
    const beta = await newProgram('nu-deux');
    await grant(accountId, alpha);
    await grant(accountId, beta);
    await app.query(
      "INSERT INTO sessions (account_id, absolute_expires_at) VALUES ($1, now() + interval '1 day')",
      [accountId],
    );

    await app.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [accountId]);

    // Les droits sont des faits de la PERSONNE : ils survivent au compte
    // (nombre de lignes ET statuts — jamais un agrégat seul).
    const grants = await grantsOf(await personOf(accountId));
    expect(grants).toHaveLength(2);
    expect(grants.map((r) => r.status)).toEqual(['ACTIVE', 'ACTIVE']);

    // La cascade des sessions, posée au LOT 1, elle, tient toujours.
    const sessions = await app.query<{ status: string }>(
      'SELECT status FROM sessions WHERE account_id = $1',
      [accountId],
    );
    expect(sessions.rows).toHaveLength(1);
    expect(sessions.rows[0]?.status).toBe('REVOKED');
  });

  test('LE TEST QUI COMPTE (décision Kevin) : le droit d\'un MINEUR survit à la désactivation du compte de son responsable', async () => {
    // Le responsable rattache son ayant droit — le chemin réel de 017.
    const responsibleAccount = await newAccount();
    const salt = generateErasureSalt();
    const year = new Date().getUTCFullYear() - 9;
    const enc = encryptCivilIdentity(crypto.encryption, salt, {
      nameComponents: ['Kabeya', 'Junior'],
      displayName: 'Kabeya Junior',
      birthDate: `${year}-03-12`,
    });
    seq += 1;
    const minor = firstRow(
      await app.query<{ dependent_person_id: string }>(
        `SELECT dependent_person_id
           FROM attach_dependent($1, $2, $3, $4, $5, $6, 'RESPONSIBLE')`,
        [
          await personOf(responsibleAccount),
          String(7_660_000_000 + seq),
          salt,
          enc.token,
          enc.encKeyId,
          enc.birthYear,
        ],
      ),
    ).dependent_person_id;

    // « Scolaria pour Junior » : le droit est accordé À LA PERSONNE du mineur.
    const programId = await newProgram('omicron');
    await grantToPerson(minor, programId);

    // Le compte du responsable meurt (perdu, compromis). RIEN à transférer :
    // les accès étaient déjà ceux de Junior — c'est la raison d'être de toute
    // la refonte (CDC §2.1.1.2).
    await app.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [
      responsibleAccount,
    ]);

    const grants = await grantsOf(minor);
    expect(grants).toHaveLength(1);
    expect(grants[0]).toMatchObject({ status: 'ACTIVE', revoke_reason: null });
    // Et le lien de responsabilité, fait de registre, est intact lui aussi (D-D).
    const link = firstRow(
      await app.query<{ status: string }>(
        'SELECT status FROM person_responsibilities WHERE dependent_person_id = $1',
        [minor],
      ),
    );
    expect(link.status).toBe('ACTIVE');
  });

  test('DELETE : rôle bridé → permission denied ; owner → P0107 (les deux tables)', async () => {
    const accountId = await newAccount();
    const programId = await newProgram('xi-trois');
    const id = await grant(accountId, programId);
    await expect(app.query('DELETE FROM program_grants WHERE id = $1', [id])).rejects.toThrow(
      /permission denied/,
    );
    await expect(
      codeOf(() => owner.query('DELETE FROM program_grants WHERE id = $1', [id])),
    ).resolves.toBe(DB_ERROR.DELETE_FORBIDDEN);
    await expect(
      codeOf(() => owner.query('DELETE FROM programs WHERE id = $1', [programId])),
    ).resolves.toBe(DB_ERROR.DELETE_FORBIDDEN);
  });

  test('§3.8 — AUCUNE colonne de facturation dans le catalogue (vérifié sur le schéma)', async () => {
    const columns = await owner.query<{ column_name: string }>(
      `SELECT column_name FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name IN ('programs', 'program_grants')`,
    );
    const forbidden = ['price', 'billing', 'renewal', 'invoice', 'amount', 'currency'];
    for (const { column_name } of columns.rows) {
      for (const marker of forbidden) {
        expect(column_name.toLowerCase()).not.toContain(marker);
      }
    }
    // Le catalogue dit « activé / désactivé », et rien de plus.
    expect(columns.rows.length).toBeGreaterThan(0);
  });
});
