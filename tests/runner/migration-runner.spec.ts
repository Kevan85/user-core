import { Pool } from 'pg';
import { runMigrations } from '../../scripts/migrate';
import { adminUrl, firstRow } from '../helpers/db';

// Les preuves du runner sont rejouées par la CI à chaque run, pas démontrées
// une fois à la main.
describe('Runner de migrations (contre le Postgres réel)', () => {
  let pool: Pool;

  beforeAll(() => {
    pool = new Pool({ connectionString: adminUrl() });
  });
  afterAll(async () => pool.end());

  test('idempotence — deux exécutions successives passent sans ré-appliquer', async () => {
    // Le schéma est déjà migré par le global-setup : ces deux runs doivent
    // être des no-ops propres.
    await expect(runMigrations(adminUrl())).resolves.toBeUndefined();
    await expect(runMigrations(adminUrl())).resolves.toBeUndefined();

    const rows = await pool.query<{ version: string }>(
      'SELECT version FROM schema_migrations ORDER BY version',
    );
    expect(rows.rows.map((r) => r.version)).toEqual([
      '001_app_role.sql',
      '002_accounts.sql',
      '003_account_secrets.sql',
      '004_sessions.sql',
      '005_error_codes.sql',
      '006_phone_claims.sql',
      '007_possession_proofs.sql',
      '008_catalog.sql',
      '009_outbox_retry.sql',
      '010_program_clients.sql',
      '011_create_account.sql',
      '012_program_invitations.sql',
      '013_program_client_assertions.sql',
      '014_persons.sql',
      '015_reference_fail_closed.sql',
      '016_accounts_person.sql',
      '017_person_responsibilities.sql',
      '018_claims_to_person.sql',
      '019_grants_to_person.sql',
      '020_emancipation.sql',
      '021_dependent_invitations.sql',
      '022_invited_dependent_identity.sql',
    ]);
  });

  test('checksum divergent — une migration modifiée après application est REFUSÉE', async () => {
    const saved = await pool.query<{ checksum: string }>(
      "SELECT checksum FROM schema_migrations WHERE version = '001_app_role.sql'",
    );
    const original = firstRow(saved).checksum;

    // On falsifie l'ENREGISTREMENT en base (jamais le fichier appliqué).
    await pool.query(
      "UPDATE schema_migrations SET checksum = 'falsifie' WHERE version = '001_app_role.sql'",
    );
    try {
      await expect(runMigrations(adminUrl())).rejects.toThrow(/modifié APRÈS application/);
    } finally {
      await pool.query('UPDATE schema_migrations SET checksum = $1 WHERE version = $2', [
        original,
        '001_app_role.sql',
      ]);
    }

    // État restauré : le runner repasse.
    await expect(runMigrations(adminUrl())).resolves.toBeUndefined();
  });
});
