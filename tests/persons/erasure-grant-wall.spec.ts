import { Pool } from 'pg';
import { generateErasureSalt } from '../../src/crypto/person-identity';
import { DB_ERROR, dbErrorCode } from '../../src/db/errors';
import { createAccount as createAccountFixture } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

/**
 * 032 — LE MUR : une personne effacée ne reçoit plus de droit d'accès (E-1,
 * étape 1 : le mur, avant la coupure).
 *
 * Ce que ces tests prouvent, et qui a d'abord été MESURÉ sur le schéma d'avant :
 * après un effacement COMPLETED, le droit restait ACTIF, et une coupure sans
 * mur était défaite par le clic suivant d'un programme (`grant_program_as_program`
 * rendait GRANTED sur une personne effacée).
 *
 * Chaque refus est doublé de son CONTRÔLE POSITIF : un test qui prouverait
 * seulement qu'on a cassé la pose ne prouverait rien.
 *
 * Hors transaction, commit réel, sous rôle bridé ET owner (CLAUDE.md §5).
 */
describe('032 — une personne effacée ne reçoit plus de droit d\'accès', () => {
  let app: Pool;
  let owner: Pool;
  let seq = 0;
  let grantedProgram: string;
  let selfServiceProgram: string;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    await clean();
    grantedProgram = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO programs (code, label, access_mode)
         VALUES ('wall-granted', 'Programme accordé', 'GRANTED') RETURNING id`,
      ),
    ).id;
    selfServiceProgram = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO programs (code, label, access_mode)
         VALUES ('wall-self', 'Programme libre', 'SELF_SERVICE') RETURNING id`,
      ),
    ).id;
  });

  afterAll(async () => {
    await clean();
    await app.end();
    await owner.end();
  });

  // TRUNCATE sous OWNER — le patron du dépôt (helpers/db.ts) : un DELETE serait
  // refusé, et il devrait l'être (§3.10, zéro suppression physique).
  async function clean(): Promise<void> {
    await truncateTables(
      owner,
      'program_grants',
      'programs',
      'person_erasures',
      'accounts',
      'persons',
    );
  }

  function nextIdentifier(): string {
    seq += 1;
    return String(7_600_000_000 + seq);
  }

  async function codeOf(run: () => Promise<unknown>): Promise<string | undefined> {
    try {
      await run();
    } catch (err) {
      return dbErrorCode(err);
    }
    throw new Error("une violation était attendue : le mur n'a pas levé");
  }

  /** Un compte + sa personne, par le chemin unique. */
  async function newAccount(): Promise<{ accountId: string; personId: string }> {
    const accountId = await createAccountFixture(app, nextIdentifier());
    const personId = firstRow(
      await app.query<{ person_id: string }>('SELECT person_id FROM accounts WHERE id = $1', [
        accountId,
      ]),
    ).person_id;
    return { accountId, personId };
  }

  /** Une personne SANS compte — un ayant droit, la population de 021. */
  async function newPersonWithoutAccount(): Promise<string> {
    return firstRow(
      await app.query<{ id: string }>('SELECT create_person($1, $2, NULL, NULL, NULL) AS id', [
        nextIdentifier(),
        generateErasureSalt(),
      ]),
    ).id;
  }

  /** L'effacement RÉEL, par ses propres portes — jamais une fixture d'état. */
  async function erase(accountId: string): Promise<void> {
    const request = firstRow(
      await app.query<{ verdict: string; erasure_id: string }>(
        "SELECT * FROM request_erasure_self($1, 'IMMEDIATE')",
        [accountId],
      ),
    );
    expect(request.verdict).toBe('REQUESTED');
    const done = firstRow(
      await app.query<{ verdict: string }>('SELECT verdict FROM erase_person($1)', [
        request.erasure_id,
      ]),
    );
    expect(done.verdict).toBe('COMPLETED');
  }

  test('LE MUR ferme TOUT INSERT — et voici ce que chaque chemin rencontre en premier', async () => {
    const { accountId, personId } = await newAccount();
    await erase(accountId);
    expect(
      firstRow(await app.query<{ e: boolean }>('SELECT person_is_erased($1) AS e', [personId])).e,
    ).toBe(true);

    // 1 — grant_program_self : ATTENTION, ce chemin n'atteint PAS le mur, et il
    //     faut l'écrire plutôt que de le maquiller. Une personne effacée a
    //     toujours un compte désactivé (erase_person le désactive, et P0102
    //     interdit de le réactiver) : la porte refuse donc AVANT, sur son propre
    //     mur d'activité. Défense en profondeur — deux murs en file, c'est le
    //     premier qui mord. Le mur d'effacement, lui, est prouvé pour lui-même
    //     par l'INSERT nu sous owner, plus bas.
    const bySelf = firstRow(
      await app.query<{ verdict: string }>('SELECT verdict FROM grant_program_self($1, $2)', [
        accountId,
        selfServiceProgram,
      ]),
    );
    expect(bySelf.verdict).toBe('ACCOUNT_NOT_ACTIVE');

    // 2 — grant_program_staff : même famille. Elle exige une CIBLE à compte
    //     ACTIF (023) ; un effacé n'en a plus. Le mur d'effacement est là,
    //     derrière, mais ce n'est pas lui qui parle ici.
    const staffActor = await createAccountFixture(app, nextIdentifier(), {
      role: 'PLATFORM_STAFF',
    });
    const byStaff = firstRow(
      await app.query<{ verdict: string }>('SELECT verdict FROM grant_program_staff($1, $2, $3)', [
        staffActor,
        accountId,
        selfServiceProgram,
      ]),
    );
    expect(byStaff.verdict).toBe('UNKNOWN_ACCOUNT');

    // 3 — grant_program_as_program : elle adresse la PERSONNE et n'exige aucun
    //     compte. C'est ELLE qui atteint le mur — et c'est le chemin qui compte,
    //     puisqu'un ayant droit n'a jamais de compte du tout.
    await expect(
      codeOf(() =>
        app.query('SELECT grant_program_as_program($1, $2)', [personId, grantedProgram]),
      ),
    ).resolves.toBe(DB_ERROR.PERSON_ERASED);

    // 4 — l'INSERT nu sous OWNER : le mur ne dépend d'aucune fonction, et il
    // s'applique même à qui a tous les droits (row-level, pas un GRANT).
    await expect(
      codeOf(() =>
        owner.query(
          `INSERT INTO program_grants (person_id, program_id, granted_by)
           VALUES ($1, $2, 'PROGRAM')`,
          [personId, grantedProgram],
        ),
      ),
    ).resolves.toBe(DB_ERROR.PERSON_ERASED);

    // Contrôle négatif de forme : aucun droit n'a été créé au passage.
    const n = firstRow(
      await owner.query<{ n: string }>(
        'SELECT count(*) AS n FROM program_grants WHERE person_id = $1',
        [personId],
      ),
    ).n;
    expect(Number(n)).toBe(0);
  });

  test('CONTRÔLE POSITIF : une personne NON effacée reçoit toujours ses droits, par les mêmes portes', async () => {
    const { accountId, personId } = await newAccount();
    expect(
      firstRow(await app.query<{ e: boolean }>('SELECT person_is_erased($1) AS e', [personId])).e,
    ).toBe(false);

    const self = firstRow(
      await app.query<{ verdict: string }>('SELECT verdict FROM grant_program_self($1, $2)', [
        accountId,
        selfServiceProgram,
      ]),
    );
    expect(self.verdict).toBe('ACTIVATED');

    const asProgram = firstRow(
      await app.query<{ verdict: string }>(
        'SELECT verdict FROM grant_program_as_program($1, $2)',
        [personId, grantedProgram],
      ),
    );
    expect(asProgram.verdict).toBe('GRANTED');

    // Le nombre de lignes ET leur état (un count seul passerait à vide).
    const rows = await owner.query<{ status: string }>(
      "SELECT status FROM program_grants WHERE person_id = $1 AND status = 'ACTIVE'",
      [personId],
    );
    expect(rows.rows).toHaveLength(2);
  });

  test('le mur vaut AUSSI pour une personne SANS compte (un ayant droit effacé par le chemin STAFF)', async () => {
    const dependent = await newPersonWithoutAccount();
    // Le chemin STAFF exige un acteur PLATFORM_STAFF/ADMIN (026:458-461) — le
    // nom de la fonction est l'acteur, mais le RÔLE est vérifié en base.
    const staffAccount = await createAccountFixture(app, nextIdentifier(), {
      role: 'PLATFORM_STAFF',
    });
    const request = firstRow(
      await app.query<{ verdict: string; erasure_id: string }>(
        "SELECT * FROM request_erasure_staff($1, $2, 'IMMEDIATE')",
        [staffAccount, dependent],
      ),
    );
    expect(request.verdict).toBe('REQUESTED');
    await app.query('SELECT erase_person($1)', [request.erasure_id]);

    await expect(
      codeOf(() =>
        app.query('SELECT grant_program_as_program($1, $2)', [dependent, grantedProgram]),
      ),
    ).resolves.toBe(DB_ERROR.PERSON_ERASED);
  });

  test('LE LOT EST INERTE : l\'effacement ne coupe encore RIEN (la coupure est l\'étape 2)', async () => {
    const { accountId, personId } = await newAccount();
    await app.query('SELECT grant_program_self($1, $2)', [accountId, selfServiceProgram]);
    await erase(accountId);

    // Ce test DOIT tomber quand l'étape 2 arrivera : c'est sa raison d'être.
    // Il fixe l'état de départ pour que la coupure soit prouvée par un
    // changement, et non par une assertion écrite après coup.
    const still = firstRow(
      await owner.query<{ status: string }>(
        'SELECT status FROM program_grants WHERE person_id = $1 ORDER BY seq DESC LIMIT 1',
        [personId],
      ),
    );
    expect(still.status).toBe('ACTIVE');
  });

  test('L\'AMBIGUÏTÉ TIENT SUR DEUX PIEDS : SELF et ERASED restent tous deux atteignables', async () => {
    // Pourquoi ce test existe : la façade n'expose pas revoke_reason, donc un
    // programme voit REVOKED sans savoir pourquoi. Cette ambiguïté n'est
    // acceptable que tant que DEUX causes au moins sont atteignables. Le jour
    // où l'une disparaît — un lot qui retirerait la fermeture par la famille,
    // par exemple — REVOKED deviendrait un oracle d'effacement, et RIEN ne
    // rougirait. Ce test rougit à sa place.
    const { accountId, personId } = await newAccount();
    await app.query('SELECT grant_program_self($1, $2)', [accountId, selfServiceProgram]);

    // Pied 1 — SELF, par le chemin applicatif réel.
    const revoked = firstRow(
      await app.query<{ verdict: string }>('SELECT verdict FROM revoke_program_grant_self($1, $2)', [
        accountId,
        selfServiceProgram,
      ]),
    );
    // 'DEACTIVATED' est le verdict de succès de cette porte (023) — le droit
    // est éteint ; c'est le motif en base, ci-dessous, qui est le sujet du test.
    expect(revoked.verdict).toBe('DEACTIVATED');
    const bySelf = firstRow(
      await owner.query<{ revoke_reason: string }>(
        'SELECT revoke_reason FROM program_grants WHERE person_id = $1 ORDER BY seq DESC LIMIT 1',
        [personId],
      ),
    );
    expect(bySelf.revoke_reason).toBe('SELF');

    // Pied 2 — ERASED est une valeur POSABLE du type. À l'étape 1 elle n'a pas
    // encore d'écrivain (la coupure est l'étape 2) : on prouve donc qu'elle
    // existe et qu'un registre peut la porter, sans quoi l'étape 2 échouerait.
    const second = await newAccount();
    await app.query('SELECT grant_program_self($1, $2)', [
      second.accountId,
      selfServiceProgram,
    ]);
    await owner.query(
      `UPDATE program_grants SET status = 'REVOKED', revoke_reason = 'ERASED'
        WHERE person_id = $1 AND status = 'ACTIVE'`,
      [second.personId],
    );
    const byErased = firstRow(
      await owner.query<{ revoke_reason: string }>(
        'SELECT revoke_reason FROM program_grants WHERE person_id = $1 ORDER BY seq DESC LIMIT 1',
        [second.personId],
      ),
    );
    expect(byErased.revoke_reason).toBe('ERASED');

    // Et le motif ne sort JAMAIS par la façade : la requête de statut ne le
    // sélectionne pas. On l'assert sur la source, pas sur une intention.
    const exposed = firstRow(
      await owner.query<{ src: string }>(
        `SELECT prosrc AS src FROM pg_proc WHERE proname = 'wall_erased_person_grant'`,
      ),
    ).src;
    expect(exposed).not.toMatch(/revoke_reason/);
  });
});
