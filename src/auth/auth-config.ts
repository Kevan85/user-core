import { createPrivateKey, createPublicKey, KeyObject } from 'crypto';
import { ConfigViolations } from '../bootstrap/assembly';

// C2 : borne DURE, dans le code, pas dans la config. La révocation serveur ne
// rattrape jamais un jeton d'accès déjà émis : sa durée de vie est le risque
// résiduel assumé, et il se borne ici. Le service REFUSE de booter au-delà.
export const MAX_ACCESS_TOKEN_TTL_SECONDS = 900;

export interface Argon2Params {
  memoryCost: number;
  timeCost: number;
  parallelism: number;
}

export interface SigningKeyPair {
  kid: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
}

/**
 * Configuration d'authentification, assemblée au boot (patron K2) :
 * incomplète ou hors bornes = REFUS de démarrer, violations listées d'un bloc.
 * C7 : les paramètres argon2id vivent ICI (config), avec des défauts
 * explicites — un durcissement futur est un changement d'env + re-hash à la
 * connexion, jamais une migration de crise.
 */
export interface AuthAssembly {
  accessTokenTtlSeconds: number;
  activeKid: string;
  keys: Map<string, SigningKeyPair>;
  argon2: Argon2Params;
  lockThreshold: number;
  lockBaseSeconds: number;
  lockCapSeconds: number;
  refreshTokenTtlSeconds: number;
  sessionAbsoluteTtlSeconds: number;
  graceWindowSeconds: number;
  throttleMaxAttempts: number;
  throttleWindowSeconds: number;
  /** Longueur minimale d'un secret choisi à l'inscription (LOT 4). */
  secretMinLength: number;
  /** Throttle DÉDIÉ de l'inscription publique : par IP, budget distinct du login. */
  registerThrottleMaxAttempts: number;
  registerThrottleWindowSeconds: number;
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

export function assembleAuthFromEnv(env: NodeJS.ProcessEnv = process.env): AuthAssembly {
  const violations: string[] = [];

  const accessTokenTtlSeconds = readInt(env, 'AUTH_ACCESS_TOKEN_TTL_SECONDS', 900, violations);
  if (accessTokenTtlSeconds > MAX_ACCESS_TOKEN_TTL_SECONDS) {
    violations.push(
      `AUTH_ACCESS_TOKEN_TTL_SECONDS=${accessTokenTtlSeconds} dépasse la borne dure de ` +
        `${MAX_ACCESS_TOKEN_TTL_SECONDS} s (15 min) — un jeton d'accès émis échappe à la ` +
        'révocation serveur : sa vie se borne ici (C2)',
    );
  }

  const keys = new Map<string, SigningKeyPair>();
  const rawKeys = env.AUTH_SIGNING_KEYS;
  const activeKid = env.AUTH_ACTIVE_KEY_ID ?? '';
  if (!rawKeys) {
    violations.push('AUTH_SIGNING_KEYS manquant (voir .env.example)');
  } else {
    try {
      const parsed: unknown = JSON.parse(rawKeys);
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('objet JSON { kid: base64 } attendu');
      }
      for (const [kid, value] of Object.entries(parsed)) {
        if (typeof value !== 'string') {
          throw new Error(`clé « ${kid} » : chaîne base64 attendue`);
        }
        const privateKey = createPrivateKey({
          key: Buffer.from(value, 'base64'),
          format: 'der',
          type: 'pkcs8',
        });
        if (privateKey.asymmetricKeyType !== 'ed25519') {
          throw new Error(`clé « ${kid} » : Ed25519 exigé (EdDSA), reçu ${privateKey.asymmetricKeyType}`);
        }
        keys.set(kid, { kid, privateKey, publicKey: createPublicKey(privateKey) });
      }
    } catch (err) {
      violations.push(
        `AUTH_SIGNING_KEYS invalide : ${err instanceof Error ? err.message : 'illisible'}`,
      );
    }
  }
  if (!activeKid) {
    violations.push('AUTH_ACTIVE_KEY_ID manquant');
  } else if (rawKeys && keys.size > 0 && !keys.has(activeKid)) {
    violations.push(`AUTH_ACTIVE_KEY_ID=« ${activeKid} » absent de AUTH_SIGNING_KEYS`);
  }

  const argon2: Argon2Params = {
    // Défauts explicites (C7) : 64 MiB, 3 passes, parallélisme 4.
    memoryCost: readInt(env, 'AUTH_ARGON2_MEMORY_COST', 65536, violations),
    timeCost: readInt(env, 'AUTH_ARGON2_TIME_COST', 3, violations),
    parallelism: readInt(env, 'AUTH_ARGON2_PARALLELISM', 4, violations),
  };

  const assembly: AuthAssembly = {
    accessTokenTtlSeconds,
    activeKid,
    keys,
    argon2,
    lockThreshold: readInt(env, 'AUTH_LOCK_THRESHOLD', 5, violations),
    lockBaseSeconds: readInt(env, 'AUTH_LOCK_BASE_SECONDS', 60, violations),
    lockCapSeconds: readInt(env, 'AUTH_LOCK_CAP_SECONDS', 3600, violations),
    refreshTokenTtlSeconds: readInt(env, 'AUTH_REFRESH_TTL_SECONDS', 604800, violations),
    sessionAbsoluteTtlSeconds: readInt(env, 'AUTH_SESSION_ABSOLUTE_TTL_SECONDS', 2592000, violations),
    graceWindowSeconds: readInt(env, 'AUTH_GRACE_WINDOW_SECONDS', 30, violations),
    throttleMaxAttempts: readInt(env, 'AUTH_THROTTLE_MAX_ATTEMPTS', 10, violations),
    throttleWindowSeconds: readInt(env, 'AUTH_THROTTLE_WINDOW_SECONDS', 60, violations),
    secretMinLength: readInt(env, 'AUTH_SECRET_MIN_LENGTH', 8, violations),
    registerThrottleMaxAttempts: readInt(env, 'AUTH_REGISTER_THROTTLE_MAX_ATTEMPTS', 5, violations),
    registerThrottleWindowSeconds: readInt(env, 'AUTH_REGISTER_THROTTLE_WINDOW_SECONDS', 3600, violations),
  };

  if (violations.length > 0) {
    throw new ConfigViolations(violations);
  }
  return assembly;
}
