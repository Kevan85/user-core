import { Pool } from 'pg';
import {
  APP_ROLE,
  assembleApiFromEnv,
  assertBridledRole,
  ConfigViolations,
} from '../../src/bootstrap/assembly';
import { adminUrl, appUrl, firstRow } from '../helpers/db';

// Le service tourne sous le rôle BRIDÉ, jamais en owner — sinon les REVOKE
// des migrations sont décoratifs à l'exécution. Ces deux preuves gardent le
// chemin de boot réel (assembleApiFromEnv + assertBridledRole), pas une copie.
describe('Rôle d\'exécution du service (boot)', () => {
  test('le pool assemblé depuis l\'env du service tourne sous user_core_app', async () => {
    const assembly = assembleApiFromEnv({ DATABASE_URL: appUrl(), PORT: '3000' });
    try {
      await expect(assertBridledRole(assembly.pool)).resolves.toBeUndefined();
      const who = firstRow(
        await assembly.pool.query<{ who: string }>('SELECT current_user AS who'),
      ).who;
      expect(who).toBe(APP_ROLE);
    } finally {
      await assembly.pool.end();
    }
  });

  test('DATABASE_URL pointant le propriétaire → le boot REFUSE (pas un log, un refus)', async () => {
    const assembly = assembleApiFromEnv({ DATABASE_URL: adminUrl(), PORT: '3000' });
    try {
      await expect(assertBridledRole(assembly.pool)).rejects.toThrow(ConfigViolations);
      await expect(assertBridledRole(assembly.pool)).rejects.toThrow(
        /doit tourner sous le rôle bridé/,
      );
    } finally {
      await assembly.pool.end();
    }
  });

  test('config incomplète → violations listées d\'un bloc', () => {
    expect(() => assembleApiFromEnv({ PORT: 'abc' })).toThrow(ConfigViolations);
    try {
      assembleApiFromEnv({ PORT: 'abc' });
    } catch (err) {
      expect((err as Error).message).toMatch(/DATABASE_URL manquant/);
      expect((err as Error).message).toMatch(/PORT invalide/);
    }
  });
});

// Pool jetable hors assemblage : vérifie que la dérivation appUrl() du harnais
// et le rôle réellement créé par 001 restent alignés.
describe('Cohérence harnais ↔ migration 001', () => {
  test('le rôle du harnais est bien celui de la migration', async () => {
    const pool = new Pool({ connectionString: appUrl() });
    try {
      const who = firstRow(await pool.query<{ who: string }>('SELECT current_user AS who')).who;
      expect(who).toBe(APP_ROLE);
    } finally {
      await pool.end();
    }
  });
});
