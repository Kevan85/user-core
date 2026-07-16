import { Pool } from 'pg';
import { DB_ERROR, dbErrorCode } from '../../src/db/errors';
import { adminUrl, firstRow } from '../helpers/db';

// C5 (Auditeur, 16/07/2026) : une consultation de référence échoue FERMÉ.
// La forme naïve (SELECT nu sur le singleton) rend NULL quand la ligne
// manque — et un NULL dans une comparaison SQL n'élève jamais : tout mur
// écrit naturellement par-dessus s'OUVRE en silence. Les deux fonctions de
// référence du dépôt doivent RAISE (P0112), jamais rendre NULL.
//
// Ces tests vident le singleton SOUS OWNER (aucun chemin applicatif ne le
// peut — REVOKE en place ; c'est le périmètre honnête du 🟠), hors de toute
// transaction de test, et restaurent l'état dans le finally.
describe('références singleton — échec FERMÉ, jamais NULL (014/015)', () => {
  let owner: Pool;

  beforeAll(() => {
    owner = new Pool({ connectionString: adminUrl() });
  });

  afterAll(async () => {
    await owner.end();
  });

  async function codeOf(run: () => Promise<unknown>): Promise<string | undefined> {
    try {
      await run();
    } catch (err) {
      return dbErrorCode(err);
    }
    throw new Error("un P0112 était attendu : la consultation a rendu une valeur");
  }

  test('active_hmac_key_id() : singleton absent → RAISE P0112, jamais NULL (015)', async () => {
    const saved = firstRow(
      await owner.query<{ hmac_key_id: string }>(
        'SELECT hmac_key_id FROM hmac_key_reference WHERE singleton',
      ),
    );
    await owner.query('DELETE FROM hmac_key_reference');
    try {
      await expect(codeOf(() => owner.query('SELECT active_hmac_key_id()'))).resolves.toBe(
        DB_ERROR.EMPTY_REFERENCE,
      );
    } finally {
      await owner.query('INSERT INTO hmac_key_reference (hmac_key_id) VALUES ($1)', [
        saved.hmac_key_id,
      ]);
    }
    // L'état est bien restauré : la garde de 006 revit.
    const restored = firstRow(
      await owner.query<{ id: string }>('SELECT active_hmac_key_id() AS id'),
    );
    expect(restored.id).toBe(saved.hmac_key_id);
  });

  test('emancipation_minimum_age() : singleton absent → RAISE P0112, jamais NULL (014)', async () => {
    const saved = firstRow(
      await owner.query<{ minimum_age_years: number }>(
        'SELECT minimum_age_years FROM emancipation_policy WHERE singleton',
      ),
    );
    await owner.query('DELETE FROM emancipation_policy');
    try {
      await expect(codeOf(() => owner.query('SELECT emancipation_minimum_age()'))).resolves.toBe(
        DB_ERROR.EMPTY_REFERENCE,
      );
    } finally {
      await owner.query('INSERT INTO emancipation_policy (minimum_age_years) VALUES ($1)', [
        saved.minimum_age_years,
      ]);
    }
    const restored = firstRow(
      await owner.query<{ age: number }>('SELECT emancipation_minimum_age() AS age'),
    );
    expect(restored.age).toBe(saved.minimum_age_years);
  });
});
