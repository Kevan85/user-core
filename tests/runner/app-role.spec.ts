import { Pool } from 'pg';
import { appUrl } from '../helpers/db';

// Le rôle applicatif bridé est un invariant de LOT 0 : le service ne se
// connecte jamais en owner. Ces preuves tournent SOUS le rôle bridé
// (CLAUDE.md §5), pas sous le rôle d'administration.
describe('Rôle applicatif user_core_app (sous rôle bridé)', () => {
  let app: Pool;

  beforeAll(() => {
    app = new Pool({ connectionString: appUrl() });
  });
  afterAll(async () => app.end());

  test('la connexion du rôle applicatif fonctionne', async () => {
    const result = await app.query<{ who: string }>('SELECT current_user AS who');
    expect(result.rows[0]?.who).toBe('user_core_app');
  });

  test('schema_migrations est INACCESSIBLE au rôle applicatif (lecture refusée)', async () => {
    await expect(app.query('SELECT version FROM schema_migrations')).rejects.toThrow(
      /permission denied/,
    );
  });

  test('schema_migrations est INALTÉRABLE par le rôle applicatif (écriture refusée)', async () => {
    await expect(
      app.query("INSERT INTO schema_migrations (version, checksum) VALUES ('999_x.sql', 'x')"),
    ).rejects.toThrow(/permission denied/);
  });
});
