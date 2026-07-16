import { randomBytes } from 'crypto';
import { Pool, PoolClient } from 'pg';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { encryptCivilIdentity, generateErasureSalt } from '../../src/crypto/person-identity';
import { DB_ERROR, dbErrorCode } from '../../src/db/errors';
import { createAccount } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// Les murs de 017. Le standard du dépôt, durci pour les triggers DIFFÉRÉS :
// le verdict tombe au COMMIT, donc les tests committent POUR DE VRAI (jamais
// de BEGIN/ROLLBACK autour d'un mur différé — il ne prouverait rien), sous
// owner, en CONTOURNANT attach_dependent() : c'est le test qui compte.
const crypto = assembleCryptoFromEnv({
  USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
  USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
  USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
  USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
});

const YEAR = new Date().getUTCFullYear();

describe('person_responsibilities — les murs (017)', () => {
  let app: Pool;
  let owner: Pool;
  let minimumAge: number;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    await truncateTables(owner, 'person_responsibilities', 'accounts', 'persons');
    minimumAge = firstRow(
      await owner.query<{ age: number }>('SELECT emancipation_minimum_age() AS age'),
    ).age;
  });

  afterAll(async () => {
    await truncateTables(owner, 'person_responsibilities', 'accounts', 'persons');
    await app.end();
    await owner.end();
  });

  function nextIdentifier(): string {
    seq += 1;
    return String(8_500_000_000 + seq);
  }

  async function codeOf(run: () => Promise<unknown>): Promise<string | undefined> {
    try {
      await run();
    } catch (err) {
      return dbErrorCode(err);
    }
    throw new Error("une violation était attendue : la garde n'a pas levé");
  }

  /** Un adulte AVEC compte actif : le seul profil qui peut être responsable. */
  async function adult(): Promise<{ accountId: string; personId: string }> {
    const accountId = await createAccount(app, nextIdentifier());
    const personId = firstRow(
      await app.query<{ person_id: string }>('SELECT person_id FROM accounts WHERE id = $1', [
        accountId,
      ]),
    ).person_id;
    return { accountId, personId };
  }

  /** Une personne identifiée SANS compte, née par le chemin unique. */
  async function person(birthYear: number | null): Promise<string> {
    if (birthYear === null) {
      return firstRow(
        await owner.query<{ id: string }>('SELECT create_person($1, $2, NULL, NULL, NULL) AS id', [
          nextIdentifier(),
          generateErasureSalt(),
        ]),
      ).id;
    }
    const salt = generateErasureSalt();
    const enc = encryptCivilIdentity(crypto.encryption, salt, {
      nameComponents: ['Composante'],
      displayName: 'Personne De Test',
      birthDate: `${birthYear}-06-15`,
    });
    return firstRow(
      await owner.query<{ id: string }>('SELECT create_person($1, $2, $3, $4, $5) AS id', [
        nextIdentifier(),
        salt,
        enc.token,
        enc.encKeyId,
        enc.birthYear,
      ]),
    ).id;
  }

  async function link(responsible: string, dependent: string, client: Pool = app): Promise<string> {
    return firstRow(
      await client.query<{ id: string }>(
        `INSERT INTO person_responsibilities (responsible_person_id, dependent_person_id, opened_by)
         VALUES ($1, $2, 'RESPONSIBLE') RETURNING id`,
        [responsible, dependent],
      ),
    ).id;
  }

  // COMMIT réel dont on attend le verdict : rend le code d'erreur du COMMIT.
  async function commitVerdict(statements: (c: PoolClient) => Promise<void>): Promise<string | undefined> {
    const client = await owner.connect();
    try {
      await client.query('BEGIN');
      await statements(client);
      try {
        await client.query('COMMIT');
        return undefined; // le commit est passé
      } catch (err) {
        return dbErrorCode(err);
      }
    } finally {
      client.release();
    }
  }

  test('attach_dependent (rôle bridé) : la personne mineure et son lien naissent ensemble, identifiés', async () => {
    const { personId } = await adult();
    const salt = generateErasureSalt();
    const enc = encryptCivilIdentity(crypto.encryption, salt, {
      nameComponents: ['Kabeya', 'Mwamba', 'Junior'],
      displayName: 'Kabeya Junior',
      birthDate: `${YEAR - 10}-03-12`,
    });
    const row = firstRow(
      await app.query<{ dependent_person_id: string; responsibility_id: string }>(
        `SELECT dependent_person_id, responsibility_id
           FROM attach_dependent($1, $2, $3, $4, $5, $6, 'RESPONSIBLE')`,
        [personId, nextIdentifier(), salt, enc.token, enc.encKeyId, enc.birthYear],
      ),
    );
    const stored = firstRow(
      await app.query<{ birth_year: number; status: string }>(
        `SELECT p.birth_year, r.status FROM persons p
          JOIN person_responsibilities r ON r.dependent_person_id = p.id
         WHERE p.id = $1`,
        [row.dependent_person_id],
      ),
    );
    expect(stored).toEqual({ birth_year: YEAR - 10, status: 'ACTIVE' });
  });

  test('attach_dependent : un ayant droit naît IDENTIFIÉ (blob, clé, année exigés)', async () => {
    const { personId } = await adult();
    await expect(
      codeOf(() =>
        app.query(`SELECT * FROM attach_dependent($1, $2, $3, NULL, NULL, NULL, 'RESPONSIBLE')`, [
          personId,
          nextIdentifier(),
          generateErasureSalt(),
        ]),
      ),
    ).resolves.toBe(DB_ERROR.VALUE_OUT_OF_BOUNDS);
  });

  test('un responsable sans compte ACTIF ne peut pas l’être — même en INSERT owner', async () => {
    const noAccount = await person(YEAR - 30);
    const minor = await person(YEAR - 10);
    await expect(codeOf(() => link(noAccount, minor, owner))).resolves.toBe(DB_ERROR.DEAD_PARENT);
  });

  test('mur de minorité : sans borne d’âge → refus ; adulte certain → refus ; FRONTIÈRE → passe (D-C ex.1 : le mur ne mord jamais le légitime)', async () => {
    const { personId } = await adult();
    // Sans birth_year : pas rattachable.
    const unbounded = await person(null);
    await expect(codeOf(() => link(personId, unbounded, owner))).resolves.toBe(
      DB_ERROR.VALUE_OUT_OF_BOUNDS,
    );
    // Adulte certain (diff > seuil) : refus, même sous owner.
    const certainAdult = await person(YEAR - minimumAge - 4);
    await expect(codeOf(() => link(personId, certainAdult, owner))).resolves.toBe(
      DB_ERROR.VALUE_OUT_OF_BOUNDS,
    );
    // Frontière (diff == seuil : peut-être encore mineur) : le mur LAISSE
    // passer — la précision au jour près est la façade du service, et un
    // mur plus dur refuserait de vrais mineurs. NE PAS LE DURCIR.
    const boundary = await person(YEAR - minimumAge);
    await expect(link(personId, boundary, owner)).resolves.toBeDefined();
  });

  test('l’ayant droit qui a un compte ACTIF est refusé net (façade immédiate de l’invariant E)', async () => {
    const { personId } = await adult();
    const autonomous = await adult();
    await expect(codeOf(() => link(personId, autonomous.personId, owner))).resolves.toBe(
      DB_ERROR.EMANCIPATION_CUT,
    );
  });

  test('LE MUR PORTEUR (différé) : un compte né pour un ayant droit ACTIF meurt AU COMMIT — sous owner, en contournant tout', async () => {
    const { personId } = await adult();
    const minor = await person(YEAR - 12);
    await link(personId, minor, owner);

    // L'INSERT direct du compte passe l'instruction… et meurt au COMMIT.
    const verdict = await commitVerdict(async (c) => {
      await c.query(
        `INSERT INTO accounts (public_identifier, role, person_id) VALUES ($1, 'ACCOUNT_HOLDER', $2)`,
        [nextIdentifier(), minor],
      );
    });
    expect(verdict).toBe(DB_ERROR.EMANCIPATION_CUT);
    // Rien n'a été retenu : la personne n'a toujours aucun compte.
    const count = firstRow(
      await owner.query<{ n: string }>('SELECT count(*) AS n FROM accounts WHERE person_id = $1', [
        minor,
      ]),
    ).n;
    expect(count).toBe('0');
  });

  test('MUR PORTEUR, autre direction : lien posé PUIS compte créé dans la même transaction → mort au commit', async () => {
    const { personId } = await adult();
    const minor = await person(YEAR - 12);

    const verdict = await commitVerdict(async (c) => {
      await c.query(
        `INSERT INTO person_responsibilities (responsible_person_id, dependent_person_id, opened_by)
         VALUES ($1, $2, 'RESPONSIBLE')`,
        [personId, minor],
      );
      await c.query(
        `INSERT INTO accounts (public_identifier, role, person_id) VALUES ($1, 'ACCOUNT_HOLDER', $2)`,
        [nextIdentifier(), minor],
      );
    });
    expect(verdict).toBe(DB_ERROR.EMANCIPATION_CUT);
  });

  test('les cycles sont structurellement morts (piège n°4) : B→A exige de B un compte qu’il ne peut pas avoir', async () => {
    const a = await adult();
    const b = await person(YEAR - 12);
    await link(a.personId, b, owner); // A→B actif

    // B (ayant droit, sans compte actif — l'invariant E le garantit) ne peut
    // pas devenir responsable de A : compte actif exigé. Tout nœud d'un
    // cycle devrait être responsable ET ayant droit : contradiction partout.
    await expect(codeOf(() => link(b, a.personId, owner))).resolves.toBe(DB_ERROR.DEAD_PARENT);

    // A→A : meurt aussi — le trigger parle AVANT le CHECK (ordre Postgres :
    // BEFORE-trigger puis contraintes), ici parce que A, adulte, a un compte
    // actif (P0113). Le CHECK reste la ceinture-bretelles sous le trigger :
    // on prouve son EXISTENCE au catalogue (il attraperait une insertion
    // faite triggers désarmés).
    await expect(codeOf(() => owner.query(
      `INSERT INTO person_responsibilities (responsible_person_id, dependent_person_id, opened_by)
       VALUES ($1, $1, 'RESPONSIBLE')`,
      [a.personId],
    ))).resolves.toBe(DB_ERROR.EMANCIPATION_CUT);
    const check = await owner.query(
      `SELECT 1 FROM pg_constraint
        WHERE conname = 'chk_responsibilities_not_self' AND contype = 'c'`,
    );
    expect(check.rows).toHaveLength(1);
  });

  test('invariant orphelin : clore le DERNIER lien actif est refusé ; le remplacement atomique passe', async () => {
    const first = await adult();
    const minor = await person(YEAR - 12);
    const linkId = await link(first.personId, minor, owner);

    // Fin sèche du seul lien : refusée au commit (P0114) — même par owner.
    await expect(
      codeOf(() =>
        owner.query(
          `UPDATE person_responsibilities SET status = 'ENDED', end_reason = 'ADMIN' WHERE id = $1`,
          [linkId],
        ),
      ),
    ).resolves.toBe(DB_ERROR.ORPHANED_DEPENDENT);

    // Remplacement DANS LA MÊME transaction : le commit passe.
    const second = await adult();
    const verdict = await commitVerdict(async (c) => {
      await c.query(
        `INSERT INTO person_responsibilities (responsible_person_id, dependent_person_id, opened_by)
         VALUES ($1, $2, 'PLATFORM_STAFF')`,
        [second.personId, minor],
      );
      await c.query(
        `UPDATE person_responsibilities SET status = 'ENDED', end_reason = 'ADMIN' WHERE id = $1`,
        [linkId],
      );
    });
    expect(verdict).toBeUndefined();

    const statuses = await owner.query<{ status: string }>(
      `SELECT status FROM person_responsibilities WHERE dependent_person_id = $1 ORDER BY seq`,
      [minor],
    );
    expect(statuses.rows.map((r) => r.status)).toEqual(['ENDED', 'ACTIVE']);
  });

  test('clore UN lien quand il en reste un autre : permis, la base horodate, le motif est exigé', async () => {
    const a = await adult();
    const b = await adult();
    const minor = await person(YEAR - 12);
    const linkA = await link(a.personId, minor, owner);
    await link(b.personId, minor, owner);

    // Sans motif : refusé.
    await expect(
      codeOf(() =>
        app.query(`UPDATE person_responsibilities SET status = 'ENDED' WHERE id = $1`, [linkA]),
      ),
    ).resolves.toBe(DB_ERROR.FORBIDDEN_TRANSITION);

    await app.query(
      `UPDATE person_responsibilities SET status = 'ENDED', end_reason = 'ADMIN' WHERE id = $1`,
      [linkA],
    );
    const row = firstRow(
      await app.query<{ age_seconds: number }>(
        `SELECT EXTRACT(EPOCH FROM (now() - ended_at))::float AS age_seconds
           FROM person_responsibilities WHERE id = $1`,
        [linkA],
      ),
    );
    expect(row.age_seconds).toBeLessThan(5);

    // Un lien clos est FIGÉ — même pour owner.
    await expect(
      codeOf(() =>
        owner.query(`UPDATE person_responsibilities SET status = 'ACTIVE' WHERE id = $1`, [linkA]),
      ),
    ).resolves.toBe(DB_ERROR.FROZEN_ROW);
  });

  test('contenu immuable et zéro suppression — même pour owner', async () => {
    const a = await adult();
    const b = await adult();
    const minor = await person(YEAR - 12);
    const linkId = await link(a.personId, minor, owner);

    await expect(
      codeOf(() =>
        owner.query(
          `UPDATE person_responsibilities SET responsible_person_id = $2 WHERE id = $1`,
          [linkId, b.personId],
        ),
      ),
    ).resolves.toBe(DB_ERROR.IMMUTABLE);

    await expect(
      app.query('DELETE FROM person_responsibilities WHERE id = $1', [linkId]),
    ).rejects.toThrow(/permission denied/);
    await expect(
      codeOf(() => owner.query('DELETE FROM person_responsibilities WHERE id = $1', [linkId])),
    ).resolves.toBe(DB_ERROR.DELETE_FORBIDDEN);
  });
});
