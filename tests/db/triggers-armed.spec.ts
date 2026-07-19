import { Pool } from 'pg';
import { adminUrl } from '../helpers/db';

// C3 (Auditeur, 16/07/2026) : la migration 018 joue DISABLE TRIGGER USER le
// temps d'un backfill (les lignes gelées par P0103 ne se backfillent pas
// triggers armés). Une migration qui désarme et OUBLIE de réarmer laisserait
// tous les invariants de la table silencieusement éteints en production,
// sans qu'aucun test fonctionnel ne rougisse — le scénario du motif F, en
// pire. Ce test rejoue l'assertion à CHAQUE run de CI, hors de toute
// transaction de test : tgenabled = 'O' (origin, armé) pour CHAQUE trigger
// des tables touchées. (pg_catalog dans tests/ est hors du périmètre des
// gardes — CLAUDE.md §3.7.)
describe('triggers réarmés après transformation (C3)', () => {
  let owner: Pool;

  beforeAll(() => {
    owner = new Pool({ connectionString: adminUrl() });
  });

  afterAll(async () => {
    await owner.end();
  });

  test.each(['phone_claims', 'possession_proof_refusals', 'outbox', 'program_grants'])(
    'chaque trigger de %s est armé (tgenabled = O)',
    async (table) => {
      const rows = await owner.query<{ tgname: string; tgenabled: string }>(
        `SELECT t.tgname, t.tgenabled
           FROM pg_trigger t
           JOIN pg_class c ON c.oid = t.tgrelid
          WHERE c.relname = $1 AND NOT t.tgisinternal`,
        [table],
      );
      // Prouver une ABSENCE d'anomalie exige de compter (piège connu) : une
      // table sans aucun trigger passerait un simple « tous à O ».
      expect(rows.rows.length).toBeGreaterThan(0);
      for (const trigger of rows.rows) {
        expect({ trigger: trigger.tgname, enabled: trigger.tgenabled }).toEqual({
          trigger: trigger.tgname,
          enabled: 'O',
        });
      }
    },
  );
});
