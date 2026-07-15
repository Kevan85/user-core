import { MAX_ACCESS_TOKEN_TTL_SECONDS } from '../auth/auth-config';
import { ConfigViolations } from '../bootstrap/assembly';

/**
 * Configuration de l'authentification des PROGRAMMES (LOT 4, étape 6) —
 * patron K2 : incomplète ou hors bornes = refus de démarrer.
 */
export interface ProgramAuthConfig {
  /** Durée de vie du jeton de programme — même borne dure C2 que les comptes. */
  tokenTtlSeconds: number;
  /** Fenêtre maximale acceptée pour l'échéance d'une assertion entrante. */
  assertionMaxTtlSeconds: number;
  throttleMaxAttempts: number;
  throttleWindowSeconds: number;
}

function readInt(
  env: NodeJS.ProcessEnv,
  name: string,
  fallback: number,
  violations: string[],
): number {
  const raw = env[name];
  if (raw === undefined || raw === '') {
    return fallback;
  }
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    violations.push(`${name} invalide : « ${raw} » (entier strictement positif attendu)`);
    return fallback;
  }
  return value;
}

export function assembleProgramAuthFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): ProgramAuthConfig {
  const violations: string[] = [];

  const tokenTtlSeconds = readInt(env, 'PROGRAM_TOKEN_TTL_SECONDS', 900, violations);
  if (tokenTtlSeconds > MAX_ACCESS_TOKEN_TTL_SECONDS) {
    violations.push(
      `PROGRAM_TOKEN_TTL_SECONDS=${tokenTtlSeconds} dépasse la borne dure de ` +
        `${MAX_ACCESS_TOKEN_TTL_SECONDS} s — un jeton émis échappe à la révocation du client : ` +
        'sa vie se borne ici (C2, même règle que les comptes)',
    );
  }

  const config: ProgramAuthConfig = {
    tokenTtlSeconds,
    assertionMaxTtlSeconds: readInt(env, 'PROGRAM_ASSERTION_MAX_TTL_SECONDS', 300, violations),
    throttleMaxAttempts: readInt(env, 'PROGRAM_TOKEN_THROTTLE_MAX_ATTEMPTS', 30, violations),
    throttleWindowSeconds: readInt(env, 'PROGRAM_TOKEN_THROTTLE_WINDOW_SECONDS', 60, violations),
  };

  if (violations.length > 0) {
    throw new ConfigViolations(violations);
  }
  return config;
}
