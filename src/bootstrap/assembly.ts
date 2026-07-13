import { Pool } from 'pg';
import { createPool } from '../db/pool';

/**
 * Assemblage de la configuration au boot (patron payment-core) : une config
 * incomplète = REFUS de démarrer, toutes les violations listées d'un bloc.
 * Jamais un service d'identité qui démarre « à moitié ».
 */
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
