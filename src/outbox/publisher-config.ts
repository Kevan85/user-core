import { ConfigViolations } from '../bootstrap/assembly';
import type { PublisherConfig } from './publisher';

export interface WorkerConfig extends PublisherConfig {
  tickIntervalMs: number;
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

/**
 * Le drainage se paramètre ; il ne se devine pas. Le plafond de tentatives est
 * la garde qui empêche un événement indélivrable de tourner en boucle sur un
 * canal payant (CDC §6.6) — un bug ne doit pas pouvoir coûter 10 000 $ dans
 * la nuit.
 */
export function assemblePublisherConfig(env: NodeJS.ProcessEnv = process.env): WorkerConfig {
  const violations: string[] = [];
  const config: WorkerConfig = {
    batchSize: readInt(env, 'OUTBOX_BATCH_SIZE', 20, violations),
    leaseSeconds: readInt(env, 'OUTBOX_LEASE_SECONDS', 120, violations),
    maxAttempts: readInt(env, 'OUTBOX_MAX_ATTEMPTS', 5, violations),
    backoffBaseSeconds: readInt(env, 'OUTBOX_BACKOFF_BASE_SECONDS', 30, violations),
    backoffCapSeconds: readInt(env, 'OUTBOX_BACKOFF_CAP_SECONDS', 3600, violations),
    tickIntervalMs: readInt(env, 'WORKER_TICK_INTERVAL_MS', 5000, violations),
  };
  if (violations.length > 0) {
    throw new ConfigViolations(violations);
  }
  return config;
}
