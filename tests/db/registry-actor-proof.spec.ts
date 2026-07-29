import { Pool } from 'pg';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { encryptCivilIdentity, generateErasureSalt } from '../../src/crypto/person-identity';
import { createAccount } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';
import { fullKeyringEnv } from '../helpers/keyring-env';

/**
 * 023 — LA PREUVE D'ACTEUR AU REGISTRE (dette /v1 ①), sous rôle bridé ET
 * owner. Ce que cette suite prouve, et rien d'autre :
 *   1. le rôle applicatif n'écrit PLUS les deux registres en direct (42501) ;
 *   2. chaque fonction estampille SON acteur — il a disparu des signatures ;
 *   3. ce que la base peut prouver, elle le prouve (rôle staff, lien actif
 *      de l'agissant, personne résolue du compte) ;
 *   4. l'ancienne forme à acteur déclaré n'existe plus.
 */
const crypto = assembleCryptoFromEnv(fullKeyringEnv());

const INSUFFICIENT_PRIVILEGE = '42501';

describe('023 — la preuve d\'acteur au registre', () => {
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

  function nextIdentifier(): string {
    seq += 1;
    return String(8_700_000_000 + seq);
  }

  async function account(role: 'ACCOUNT_HOLDER' | 'PLATFORM_STAFF' = 'ACCOUNT_HOLDER'): Promise<{
    accountId: string;
    personId: string;
  }> {
    const accountId = await createAccount(app, nextIdentifier(), { role });
    const personId = firstRow(
      await app.query<{ person_id: string }>('SELECT person_id FROM accounts WHERE id = $1', [
        accountId,
      ]),
    ).person_id;
    return { accountId, personId };
  }

  async function program(mode: 'SELF_SERVICE' | 'GRANTED' = 'SELF_SERVICE'): Promise<string> {
    seq += 1;
    return firstRow(
      await owner.query<{ id: string }>(
        'INSERT INTO programs (code, label, access_mode) VALUES ($1, $2, $3) RETURNING id',
        [`prog-acteur-${seq}`, 'P', mode],
      ),
    ).id;
  }

  async function attachMinor(responsibleAccountId: string): Promise<string> {
    const salt = generateErasureSalt();
    const enc = encryptCivilIdentity(crypto.encryption, salt, {
      nameComponents: ['Composante'],
      displayName: 'Mineur De Test',
      birthDate: `${new Date().getUTCFullYear() - 10}-03-12`,
    });
    return firstRow(
      await app.query<{ dependent_person_id: string }>(
        'SELECT dependent_person_id FROM attach_dependent($1, $2, $3, $4, $5, $6)',
        [responsibleAccountId, nextIdentifier(), salt, enc.token, enc.encKeyId, enc.birthYear],
      ),
    ).dependent_person_id;
  }

  test('le rôle bridé ne touche plus program_grants : INSERT et UPDATE directs → 42501', async () => {
    const { accountId, personId } = await account();
    const programId = await program();
    await expect(
      app.query(
        "INSERT INTO program_grants (person_id, program_id, granted_by) VALUES ($1, $2, 'SELF')",
        [personId, programId],
      ),
    ).rejects.toMatchObject({ code: INSUFFICIENT_PRIVILEGE });

    await app.query('SELECT verdict FROM grant_program_self($1, $2)', [accountId, programId]);
    await expect(
      app.query(
        "UPDATE program_grants SET status = 'REVOKED', revoke_reason = 'SELF' WHERE person_id = $1",
        [personId],
      ),
    ).rejects.toMatchObject({ code: INSUFFICIENT_PRIVILEGE });
  });

  test('le rôle bridé n\'insère plus person_responsibilities en direct → 42501', async () => {
    const responsible = await account();
    const minor = await attachMinor(responsible.accountId);
    const other = await account();
    await expect(
      app.query(
        `INSERT INTO person_responsibilities (responsible_person_id, dependent_person_id, opened_by)
         VALUES ($1, $2, 'RESPONSIBLE')`,
        [other.personId, minor],
      ),
    ).rejects.toMatchObject({ code: INSUFFICIENT_PRIVILEGE });
  });

  test('grant_program_self : la personne est résolue du compte, l\'acteur SELF est estampillé par la base', async () => {
    const { accountId, personId } = await account();
    const programId = await program();
    const verdict = firstRow(
      await app.query<{ verdict: string }>('SELECT verdict FROM grant_program_self($1, $2)', [
        accountId,
        programId,
      ]),
    ).verdict;
    expect(verdict).toBe('ACTIVATED');
    const row = firstRow(
      await app.query<{ person_id: string; granted_by: string }>(
        'SELECT person_id, granted_by FROM program_grants WHERE program_id = $1',
        [programId],
      ),
    );
    expect(row).toEqual({ person_id: personId, granted_by: 'SELF' });
  });

  test('grant_program_staff : le contrôle de rôle vit EN BASE — un titulaire est refusé, rien n\'est écrit', async () => {
    const holder = await account('ACCOUNT_HOLDER');
    const target = await account();
    const programId = await program('GRANTED');
    const verdict = firstRow(
      await app.query<{ verdict: string }>(
        'SELECT verdict FROM grant_program_staff($1, $2, $3)',
        [holder.accountId, target.accountId, programId],
      ),
    ).verdict;
    expect(verdict).toBe('FORBIDDEN');
    // L'absence se prouve en comptant les lignes, jamais par un agrégat seul.
    const rows = await owner.query('SELECT 1 FROM program_grants WHERE program_id = $1', [
      programId,
    ]);
    expect(rows.rows).toHaveLength(0);
  });

  test('grant_program_staff : un staff ACTIF passe, et le registre porte PLATFORM_STAFF', async () => {
    const staff = await account('PLATFORM_STAFF');
    const target = await account();
    const programId = await program('GRANTED');
    const verdict = firstRow(
      await app.query<{ verdict: string }>(
        'SELECT verdict FROM grant_program_staff($1, $2, $3)',
        [staff.accountId, target.accountId, programId],
      ),
    ).verdict;
    expect(verdict).toBe('GRANTED');
    const row = firstRow(
      await app.query<{ granted_by: string; person_id: string }>(
        'SELECT granted_by, person_id FROM program_grants WHERE program_id = $1',
        [programId],
      ),
    );
    expect(row).toEqual({ granted_by: 'PLATFORM_STAFF', person_id: target.personId });
  });

  test('un staff DÉSACTIVÉ ne passe plus (le mur lit le statut, pas seulement le rôle)', async () => {
    const staff = await account('PLATFORM_STAFF');
    const target = await account();
    const programId = await program('GRANTED');
    await app.query("UPDATE accounts SET status = 'DEACTIVATED' WHERE id = $1", [staff.accountId]);
    const verdict = firstRow(
      await app.query<{ verdict: string }>(
        'SELECT verdict FROM grant_program_staff($1, $2, $3)',
        [staff.accountId, target.accountId, programId],
      ),
    ).verdict;
    expect(verdict).toBe('FORBIDDEN');
  });

  test('les révocations estampillent leur motif : SELF par le chemin famille, PROGRAM par le chemin programme', async () => {
    const family = await account();
    const programId = await program('GRANTED');
    await app.query('SELECT verdict FROM grant_program_as_program($1, $2)', [
      family.personId,
      programId,
    ]);
    const revoked = firstRow(
      await app.query<{ verdict: string }>(
        'SELECT verdict FROM revoke_program_grant_self($1, $2)',
        [family.accountId, programId],
      ),
    ).verdict;
    expect(revoked).toBe('DEACTIVATED');
    const row = firstRow(
      await app.query<{ granted_by: string; revoke_reason: string }>(
        'SELECT granted_by, revoke_reason FROM program_grants WHERE program_id = $1 ORDER BY seq DESC LIMIT 1',
        [programId],
      ),
    );
    expect(row).toEqual({ granted_by: 'PROGRAM', revoke_reason: 'SELF' });

    // La famille a fermé : le programme ne rouvre pas (la matrice, à travers
    // la fonction) — puis, sur une réouverture SELF, le programme révoque et
    // le motif PROGRAM est posé par SA fonction.
    await expect(
      app.query('SELECT verdict FROM grant_program_as_program($1, $2)', [
        family.personId,
        programId,
      ]),
    ).rejects.toMatchObject({ code: 'P0110' });
    await app.query('SELECT verdict FROM grant_program_self($1, $2)', [
      family.accountId,
      programId,
    ]);
    await app.query('SELECT verdict FROM revoke_program_grant_as_program($1, $2)', [
      family.personId,
      programId,
    ]);
    const last = firstRow(
      await app.query<{ revoke_reason: string }>(
        'SELECT revoke_reason FROM program_grants WHERE program_id = $1 ORDER BY seq DESC LIMIT 1',
        [programId],
      ),
    );
    expect(last.revoke_reason).toBe('PROGRAM');
  });

  test('open_responsibility_by_responsible : un agissant SANS lien actif est refusé par la BASE, rien n\'est écrit', async () => {
    const responsible = await account();
    const minor = await attachMinor(responsible.accountId);
    const stranger = await account();
    const co = await account();

    const row = firstRow(
      await app.query<{ verdict: string; responsibility_id: string | null }>(
        'SELECT verdict, responsibility_id FROM open_responsibility_by_responsible($1, $2, $3)',
        [stranger.accountId, co.personId, minor],
      ),
    );
    expect(row.verdict).toBe('NOT_RESPONSIBLE');
    expect(row.responsibility_id).toBeNull();
    const links = await owner.query(
      'SELECT 1 FROM person_responsibilities WHERE dependent_person_id = $1',
      [minor],
    );
    expect(links.rows).toHaveLength(1); // le seul lien : celui du rattachement
  });

  test('open_responsibility_by_responsible : un responsable en place ajoute, et le registre porte RESPONSIBLE', async () => {
    const responsible = await account();
    const minor = await attachMinor(responsible.accountId);
    const co = await account();

    const row = firstRow(
      await app.query<{ verdict: string; responsibility_id: string | null }>(
        'SELECT verdict, responsibility_id FROM open_responsibility_by_responsible($1, $2, $3)',
        [responsible.accountId, co.personId, minor],
      ),
    );
    expect(row.verdict).toBe('OPENED');
    expect(row.responsibility_id).not.toBeNull();
    const opened = firstRow(
      await app.query<{ opened_by: string; responsible_person_id: string }>(
        'SELECT opened_by, responsible_person_id FROM person_responsibilities WHERE id = $1',
        [row.responsibility_id],
      ),
    );
    expect(opened).toEqual({ opened_by: 'RESPONSIBLE', responsible_person_id: co.personId });
  });

  test('attach_dependent estampille RESPONSIBLE et lie à la personne du COMPTE agissant', async () => {
    const responsible = await account();
    const minor = await attachMinor(responsible.accountId);
    const link = firstRow(
      await app.query<{ opened_by: string; responsible_person_id: string }>(
        'SELECT opened_by, responsible_person_id FROM person_responsibilities WHERE dependent_person_id = $1',
        [minor],
      ),
    );
    expect(link).toEqual({
      opened_by: 'RESPONSIBLE',
      responsible_person_id: responsible.personId,
    });
  });

  test('l\'ancienne forme à acteur DÉCLARÉ n\'existe plus (aucune attach_dependent à 7 paramètres)', async () => {
    const rows = await owner.query<{ nargs: number }>(
      `SELECT pronargs AS nargs FROM pg_proc WHERE proname = 'attach_dependent'`,
    );
    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0]?.nargs).toBe(6);
  });
});
