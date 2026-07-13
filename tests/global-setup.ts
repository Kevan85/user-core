import 'dotenv/config';
import { Client } from 'pg';
import { runMigrations } from '../scripts/migrate';
import { adminUrl, appPassword } from './helpers/db';

// Une seule fois avant toutes les suites : schéma migré + mot de passe du rôle
// applicatif posé HORS migration (001 crée le rôle LOGIN sans mot de passe ;
// dev/CI le pose ici, prod via Vault).
export default async function globalSetup(): Promise<void> {
  await runMigrations(adminUrl());

  const admin = new Client({ connectionString: adminUrl() });
  await admin.connect();
  try {
    const escaped = appPassword().replace(/'/g, "''");
    await admin.query(`ALTER ROLE user_core_app PASSWORD '${escaped}'`);
  } finally {
    await admin.end();
  }
}
