import { Pool } from 'pg';
import { CatalogService } from '../../src/catalog/catalog.service';
import { createAccount as createAccountFixture } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// Le mode d'accès et la règle de réactivation vivent EN BASE : ces tests
// exercent le service, mais ce sont les triggers de 008 qui tranchent.
describe('CatalogService', () => {
  let app: Pool;
  let owner: Pool;
  let catalog: CatalogService;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    catalog = new CatalogService(app);
  });

  beforeEach(async () => {
    await truncateTables(owner, 'program_grants', 'programs', 'accounts');
  });

  afterAll(async () => {
    await app.end();
    await owner.end();
  });

  async function newAccount(
    role: 'ACCOUNT_HOLDER' | 'PLATFORM_STAFF' | 'PLATFORM_ADMIN' = 'ACCOUNT_HOLDER',
  ): Promise<string> {
    seq += 1;
    // Depuis 011, le chemin unique — les fixtures l'empruntent comme le service.
    return createAccountFixture(app, String(7700000000 + seq), { role });
  }

  async function newProgram(code: string, mode: 'SELF_SERVICE' | 'GRANTED'): Promise<string> {
    return firstRow(
      await owner.query<{ id: string }>(
        'INSERT INTO programs (code, label, access_mode) VALUES ($1, $2, $3) RETURNING id',
        [code, `Programme ${code}`, mode],
      ),
    ).id;
  }

  async function grantsOf(accountId: string): Promise<
    { status: string; granted_by: string; revoke_reason: string | null }[]
  > {
    const r = await app.query<{ status: string; granted_by: string; revoke_reason: string | null }>(
      `SELECT status, granted_by, revoke_reason FROM program_grants
        WHERE account_id = $1 ORDER BY granted_at, id`,
      [accountId],
    );
    return r.rows;
  }

  test('SELF_SERVICE — la famille ouvre et ferme librement, autant de fois qu\'elle veut', async () => {
    const accountId = await newAccount();
    await newProgram('libre-app', 'SELF_SERVICE');

    expect((await catalog.activate(accountId, 'libre-app')).outcome).toBe('ACTIVATED');
    expect((await catalog.activate(accountId, 'libre-app')).outcome).toBe('ALREADY_ACTIVE');
    expect((await catalog.deactivate(accountId, 'libre-app')).outcome).toBe('DEACTIVATED');
    expect((await catalog.activate(accountId, 'libre-app')).outcome).toBe('ACTIVATED');

    const history = await grantsOf(accountId);
    expect(history).toHaveLength(2); // append-only : deux lignes, pas un écrasement
    expect(history[0]).toMatchObject({ status: 'REVOKED', revoke_reason: 'SELF' });
    expect(history[1]).toMatchObject({ status: 'ACTIVE', granted_by: 'SELF' });
  });

  test('GRANTED — la famille NE PEUT PAS s\'ouvrir un programme accordé (aucun droit antérieur)', async () => {
    const accountId = await newAccount();
    await newProgram('sur-accord', 'GRANTED');

    const result = await catalog.activate(accountId, 'sur-accord');
    expect(result.outcome).toBe('NOT_SELF_SERVICE');
    expect(await grantsOf(accountId)).toHaveLength(0);
  });

  test('GRANTED — le staff ouvre ; la famille peut TOUJOURS se désactiver ; puis SE REMETTRE', async () => {
    const family = await newAccount();
    const staff = await newAccount('PLATFORM_STAFF');
    await newProgram('scolarite', 'GRANTED');

    expect((await catalog.grantAsStaff(staff, family, 'scolarite')).outcome).toBe('GRANTED');

    // C'est son compte : elle retire le programme de son écran, toujours.
    expect((await catalog.deactivate(family, 'scolarite')).outcome).toBe('DEACTIVATED');

    // Et elle revient sur SA décision : permis, car c'est ELLE qui avait coupé.
    expect((await catalog.activate(family, 'scolarite')).outcome).toBe('ACTIVATED');

    const history = await grantsOf(family);
    expect(history).toHaveLength(2);
    expect(history[0]).toMatchObject({ granted_by: 'PLATFORM_STAFF', revoke_reason: 'SELF' });
    expect(history[1]).toMatchObject({ status: 'ACTIVE', granted_by: 'SELF' });
  });

  test('🔴 LE PIÈGE — le tiers coupe (ADMIN) : la famille ne peut PAS se remettre toute seule', async () => {
    const family = await newAccount();
    const staff = await newAccount('PLATFORM_STAFF');
    const programId = await newProgram('scolarite-2', 'GRANTED');
    await catalog.grantAsStaff(staff, family, 'scolarite-2');

    // L'école retire l'accès (un parent exclu, un impayé traité ailleurs…).
    await app.query(
      `UPDATE program_grants SET status = 'REVOKED', revoke_reason = 'ADMIN'
        WHERE account_id = $1 AND program_id = $2 AND status = 'ACTIVE'`,
      [family, programId],
    );

    // Le parent exclu tente de se ré-inscrire seul : REFUSÉ PAR LA BASE.
    const retry = await catalog.activate(family, 'scolarite-2');
    expect(retry.outcome).toBe('REVOKED_BY_THIRD_PARTY');

    // Aucun droit actif n'est apparu.
    const history = await grantsOf(family);
    expect(history).toHaveLength(1);
    expect(history[0]).toMatchObject({ status: 'REVOKED', revoke_reason: 'ADMIN' });
  });

  test('le piège tient aussi après un cycle SELF : c\'est le DERNIER retrait qui décide', async () => {
    const family = await newAccount();
    const staff = await newAccount('PLATFORM_STAFF');
    const programId = await newProgram('scolarite-3', 'GRANTED');

    await catalog.grantAsStaff(staff, family, 'scolarite-3');
    await catalog.deactivate(family, 'scolarite-3'); // SELF
    await catalog.activate(family, 'scolarite-3'); // permis
    // Puis l'école coupe pour de bon.
    await app.query(
      `UPDATE program_grants SET status = 'REVOKED', revoke_reason = 'ADMIN'
        WHERE account_id = $1 AND program_id = $2 AND status = 'ACTIVE'`,
      [family, programId],
    );

    // Le droit le PLUS RÉCENT a été retiré par un tiers : refus.
    expect((await catalog.activate(family, 'scolarite-3')).outcome).toBe('REVOKED_BY_THIRD_PARTY');
  });

  test('F3 — révoquer et réaccorder DANS LA MÊME TRANSACTION : le verdict ne dépend pas du hasard', async () => {
    // now() est l'horodatage de la TRANSACTION : les deux lignes ci-dessous
    // portent le MÊME granted_at. Un départage par id (uuid aléatoire) ferait
    // du verdict « qui a retiré cet accès en dernier » un tirage au sort — et
    // une famille exclue par l'école pourrait se rouvrir l'accès une fois sur
    // deux. L'ordre monotone (seq) supprime le dé.
    for (let round = 0; round < 20; round++) {
      const family = await newAccount();
      const staff = await newAccount('PLATFORM_STAFF');
      const programId = await newProgram(`ecole-${round}`, 'GRANTED');
      await catalog.grantAsStaff(staff, family, `ecole-${round}`);

      const client = await app.connect();
      try {
        await client.query('BEGIN');
        // La famille se coupe…
        await client.query(
          `UPDATE program_grants SET status = 'REVOKED', revoke_reason = 'SELF'
            WHERE account_id = $1 AND program_id = $2 AND status = 'ACTIVE'`,
          [family, programId],
        );
        // …le staff la remet dans la MÊME transaction…
        await client.query(
          `INSERT INTO program_grants (account_id, program_id, granted_by)
           VALUES ($1, $2, 'PLATFORM_STAFF')`,
          [family, programId],
        );
        // …puis l'école la coupe pour de bon, toujours dans la même transaction.
        await client.query(
          `UPDATE program_grants SET status = 'REVOKED', revoke_reason = 'ADMIN'
            WHERE account_id = $1 AND program_id = $2 AND status = 'ACTIVE'`,
          [family, programId],
        );
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      } finally {
        client.release();
      }

      // Les trois lignes ont le même granted_at. Le dernier retrait est ADMIN :
      // la famille NE PEUT PAS se remettre — systématiquement, sans exception.
      const retry = await catalog.activate(family, `ecole-${round}`);
      expect(retry.outcome).toBe('REVOKED_BY_THIRD_PARTY');
    }
  });

  test('BOLA — un compte n\'active/désactive que POUR LUI-MÊME ; le staff seul peut ouvrir pour autrui', async () => {
    const victim = await newAccount();
    const attacker = await newAccount();
    await newProgram('libre-2', 'SELF_SERVICE');
    await newProgram('accorde-2', 'GRANTED');

    // L'attaquant n'a aucun moyen de nommer le compte de la victime : le
    // compte vient du jeton. Le seul chemin « pour autrui » est réservé au
    // staff — et il le refuse.
    const stolen = await catalog.grantAsStaff(attacker, victim, 'accorde-2');
    expect(stolen.outcome).toBe('FORBIDDEN');

    await catalog.activate(attacker, 'libre-2');
    // La victime n'a RIEN (nombre de lignes des deux côtés).
    expect(await grantsOf(victim)).toHaveLength(0);
    expect(await grantsOf(attacker)).toHaveLength(1);
  });

  test('la vue du catalogue dit « activé / non activé », et RIEN d\'autre (§3.8)', async () => {
    const accountId = await newAccount();
    await newProgram('alpha-vue', 'SELF_SERVICE');
    await newProgram('beta-vue', 'GRANTED');
    await catalog.activate(accountId, 'alpha-vue');

    const view = await catalog.list(accountId);
    expect(view).toHaveLength(2);
    expect(view[0]).toEqual({
      code: 'alpha-vue',
      label: 'Programme alpha-vue',
      accessMode: 'SELF_SERVICE',
      activated: true,
    });
    expect(view[1]?.activated).toBe(false);
    // Aucun champ de facturation ne peut apparaître : la forme est close.
    for (const program of view) {
      expect(Object.keys(program).sort()).toEqual([
        'accessMode',
        'activated',
        'code',
        'label',
      ]);
    }
  });

  test('programme inconnu ou retiré → refus propre, aucune ligne', async () => {
    const accountId = await newAccount();
    expect((await catalog.activate(accountId, 'fantome')).outcome).toBe('UNKNOWN_PROGRAM');
    expect((await catalog.deactivate(accountId, 'fantome')).outcome).toBe('UNKNOWN_PROGRAM');
    expect(await grantsOf(accountId)).toHaveLength(0);
  });
});
