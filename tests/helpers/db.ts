import { Pool } from 'pg';

// noUncheckedIndexedAccess : rows[0] est T | undefined. En test, une ligne
// attendue absente est une ERREUR franche, pas un undefined silencieux.
export function firstRow<T>(result: { rows: T[] }): T {
  const row = result.rows[0];
  if (row === undefined) {
    throw new Error('Résultat vide : une ligne était attendue');
  }
  return row;
}

// URL propriétaire : migrations et outillage de test UNIQUEMENT. Le service,
// lui, ne lit que DATABASE_URL (rôle bridé) — voir src/bootstrap/assembly.ts.
export function adminUrl(): string {
  const url = process.env.DATABASE_ADMIN_URL;
  if (!url) {
    throw new Error('DATABASE_ADMIN_URL manquant (voir .env.example)');
  }
  return url;
}

// Mot de passe du rôle applicatif pour dev/CI UNIQUEMENT : posé par le harnais
// (global-setup) via ALTER ROLE, jamais par une migration (001). Les secrets
// réels vivent dans Vault — celui-ci n'ouvre qu'un rôle sans privilège de
// mutation sur une base locale jetable.
export function appPassword(): string {
  return process.env.USER_CORE_APP_PASSWORD ?? 'user_core_app_dev_only';
}

export function appUrl(): string {
  const url = new URL(adminUrl());
  url.username = 'user_core_app';
  url.password = appPassword();
  return url.toString();
}

// Nettoyage inter-tests par TRUNCATE sous OWNER — légal et voulu : les REVOKE
// TRUNCATE ne visent que user_core_app ; les triggers append-only sont
// row-level et TRUNCATE, statement-level, ne les déclenche pas. C'est
// précisément le trou fermé côté rôle applicatif ; l'owner le conserve pour
// l'outillage de test.
export async function truncateTables(pool: Pool, ...tables: string[]): Promise<void> {
  await pool.query(`TRUNCATE ${tables.join(', ')} CASCADE`);
}
