import { Pool } from 'pg';
import { createPool } from '../db/pool';

/**
 * Assemblage de la configuration au boot (patron payment-core) : une config
 * incomplète = REFUS de démarrer, toutes les violations listées d'un bloc.
 * Jamais un service d'identité qui démarre « à moitié ».
 *
 * Deux URL, deux rôles, deux usages :
 *   - DATABASE_URL       → rôle bridé user_core_app : le service, et lui seul.
 *   - DATABASE_ADMIN_URL → propriétaire : migrations et harnais de test
 *     UNIQUEMENT. Le service ne la lit jamais.
 * En owner, les REVOKE n'existent plus : append-only, GRANT colonne par
 * colonne, interdiction de TRUNCATE — tout deviendrait décoratif à
 * l'exécution. D'où assertBridledRole : l'erreur est non représentable,
 * pas une convention d'environnement.
 */
export const APP_ROLE = 'user_core_app';

export interface ApiAssembly {
  pool: Pool;
  port: number;
}

export class ConfigViolations extends Error {
  constructor(violations: string[]) {
    super(`Configuration invalide :\n- ${violations.join('\n- ')}`);
    this.name = 'ConfigViolations';
  }
}

export function assembleApiFromEnv(env: NodeJS.ProcessEnv = process.env): ApiAssembly {
  const violations: string[] = [];

  const connectionString = env.DATABASE_URL;
  if (!connectionString) {
    violations.push('DATABASE_URL manquant (voir .env.example)');
  }

  const portRaw = env.PORT ?? '3000';
  const port = Number(portRaw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    violations.push(`PORT invalide : « ${portRaw} »`);
  }

  if (violations.length > 0 || !connectionString) {
    throw new ConfigViolations(violations);
  }

  return { pool: createPool(connectionString), port };
}

// Avant d'accepter le moindre trafic : le service REFUSE de tourner sous un
// autre rôle que le rôle bridé. Une DATABASE_URL mal remplie en prod ne doit
// pas pouvoir donner les pleins pouvoirs au service.
export async function assertBridledRole(pool: Pool): Promise<void> {
  const result = await pool.query<{ who: string }>('SELECT current_user AS who');
  const who = result.rows[0]?.who ?? '(inconnu)';
  if (who !== APP_ROLE) {
    throw new ConfigViolations([
      `le service doit tourner sous le rôle bridé « ${APP_ROLE} », pas « ${who} » — ` +
        'DATABASE_URL pointe un autre rôle (le propriétaire ne sert qu\'à DATABASE_ADMIN_URL)',
    ]);
  }
}
