import { Pool } from 'pg';
import { DB_ERROR, dbErrorCode } from '../../src/db/errors';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// Invariants de 008, sous rôle bridé ET sous owner. Le catalogue est un DROIT
// D'ACCÈS : activé / désactivé, historisé, jamais un facturier.
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
    await truncateTables(owner, 'program_grants', 'programs', 'accounts');
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
        [String(7600000000 + seq)],
      ),
    ).id;
  }

  // Le programme est une DONNÉE : on l'ajoute par un INSERT (acte
  // d'administration, sous owner), jamais par une migration.
  async function newProgram(code: string): Promise<string> {
    return firstRow(
      await owner.query<{ id: string }>(
        'INSERT INTO programs (code, label) VALUES ($1, $2) RETURNING id',
        [code, `Programme ${code}`],
      ),
    ).id;
  }

  async function grant(accountId: string, programId: string): Promise<string> {
    return firstRow(
      await app.query<{ id: string }>(
        'INSERT INTO program_grants (account_id, program_id) VALUES ($1, $2) RETURNING id',
        [accountId, programId],
      ),
    ).id;
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
      app.query("INSERT INTO programs (code, label) VALUES ('pirate', 'x')"),
    ).rejects.toThrow(/permission denied/);
    await expect(
      app.query("UPDATE programs SET code = 'autre' WHERE id = $1", [id]),
    ).rejects.toThrow(/permission denied/);
    await expect(app.query('DELETE FROM programs WHERE id = $1', [id])).rejects.toThrow(
      /permission denied/,
    );
  });

  test('un droit ACTIVE unique par (compte, programme)', async () => {
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

    const rows = await app.query<{ status: string; revoke_reason: string | null }>(
      'SELECT status, revoke_reason FROM program_grants WHERE account_id = $1 ORDER BY granted_at',
      [accountId],
    );
    expect(rows.rows).toHaveLength(2);
    expect(rows.rows[0]).toMatchObject({ status: 'REVOKED', revoke_reason: 'SELF' });
    expect(rows.rows[1]).toMatchObject({ status: 'ACTIVE', revoke_reason: null });
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

  test('contenu immuable : on ne « déplace » pas un droit d\'un compte à un autre', async () => {
    const accountId = await newAccount();
    const other = await newAccount();
    const programId = await newProgram('theta');
    const id = await grant(accountId, programId);
    await expect(
      codeOf(() =>
        owner.query('UPDATE program_grants SET account_id = $2 WHERE id = $1', [id, other]),
      ),
    ).resolves.toBe(DB_ERROR.IMMUTABLE);
  });

  test('aucun droit ne naît sous un compte désactivé, ni sous un programme retiré', async () => {
    const accountId = await newAccount();
    const programId = await newProgram('iota');
    await app.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [accountId]);
    await expect(codeOf(() => grant(accountId, programId))).resolves.toBe(DB_ERROR.DEAD_PARENT);

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
    const row = firstRow(
      await app.query<{ status: string }>(
        'SELECT status FROM program_grants WHERE account_id = $1',
        [accountId],
      ),
    );
    expect(row.status).toBe('ACTIVE');
  });

  test('cascade C13 — compte désactivé : sessions, revendication ET droits tombent ensemble', async () => {
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

    const grants = await app.query<{ status: string; revoke_reason: string }>(
      'SELECT status, revoke_reason FROM program_grants WHERE account_id = $1',
      [accountId],
    );
    expect(grants.rows).toHaveLength(2);
    expect(grants.rows.map((r) => r.status)).toEqual(['REVOKED', 'REVOKED']);
    expect(grants.rows.map((r) => r.revoke_reason)).toEqual([
      'ACCOUNT_DEACTIVATED',
      'ACCOUNT_DEACTIVATED',
    ]);

    // Et la cascade des sessions, posée au LOT 1, n'a pas été cassée.
    const sessions = await app.query<{ status: string }>(
      'SELECT status FROM sessions WHERE account_id = $1',
      [accountId],
    );
    expect(sessions.rows).toHaveLength(1);
    expect(sessions.rows[0]?.status).toBe('REVOKED');
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
