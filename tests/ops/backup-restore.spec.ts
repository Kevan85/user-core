import { spawnSync } from 'child_process';
import { readFileSync } from 'fs';
import { mkdtemp, readdir, stat, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { Pool } from 'pg';
import { dumpFileName, dumpTimestamp, runBackup } from '../../scripts/backup-db';
import { createAccount } from '../helpers/accounts';
import { adminUrl, appUrl, firstRow } from '../helpers/db';

/**
 * ÉTAPE 6 — LA RESTAURATION SE JOUE, elle ne se documente pas : un cycle
 * RÉEL — dump → base neuve → migrations vérifiées → données relues — rejoué
 * à chaque CI. Une procédure jamais exécutée est une hypothèse.
 *
 * Outillage à deux chemins, détection DÉTERMINISTE : le conteneur de dev
 * s'il répond (pg_dump 15, celui du serveur), sinon les binaires du PATH
 * (la CI ubuntu porte un client ≥ 15). Jamais un mélange.
 */
const RESTORE_DB = 'user_core_restore';

type Tooling =
  | { mode: 'docker' }
  | { mode: 'direct'; adminUrl: string };

function detectTooling(): Tooling {
  const probe = spawnSync('docker', ['exec', 'user-core-postgres', 'pg_dump', '--version'], {
    encoding: 'utf8',
  });
  if (probe.status === 0) {
    return { mode: 'docker' };
  }
  return { mode: 'direct', adminUrl: adminUrl() };
}

function dumpCommand(tooling: Tooling): string[] {
  return tooling.mode === 'docker'
    ? ['docker', 'exec', 'user-core-postgres', 'pg_dump', '--format=custom', '-U', 'user_core', 'user_core']
    : ['pg_dump', '--format=custom', '--dbname', tooling.adminUrl];
}

function urlForDb(base: string, db: string): string {
  const url = new URL(base);
  url.pathname = `/${db}`;
  return url.toString();
}

function psql(tooling: Tooling, db: string, sql: string): string {
  const argv =
    tooling.mode === 'docker'
      ? ['docker', 'exec', 'user-core-postgres', 'psql', '-U', 'user_core', '-d', db, '-v', 'ON_ERROR_STOP=1', '-tA', '-c', sql]
      : ['psql', urlForDb(tooling.adminUrl, db), '-v', 'ON_ERROR_STOP=1', '-tA', '-c', sql];
  const [head, ...rest] = argv as [string, ...string[]];
  const result = spawnSync(head, rest, { encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`psql (${db}) : ${result.stderr}`);
  }
  return result.stdout.trim();
}

function restoreDump(tooling: Tooling, dumpFile: string): void {
  if (tooling.mode === 'docker') {
    const catFile = spawnSync(
      'docker',
      ['exec', '-i', 'user-core-postgres', 'pg_restore', '-U', 'user_core', '-d', RESTORE_DB],
      { input: readFileSync(dumpFile) },
    );
    if (catFile.status !== 0) {
      throw new Error(`pg_restore (docker) : ${catFile.stderr.toString()}`);
    }
    return;
  }
  const result = spawnSync(
    'pg_restore',
    ['--dbname', urlForDb(tooling.adminUrl, RESTORE_DB), dumpFile],
    { encoding: 'utf8' },
  );
  if (result.status !== 0) {
    throw new Error(`pg_restore : ${result.stderr}`);
  }
}

describe('étape 6 — sauvegarde, rétention R, restauration JOUÉE', () => {
  test('la rétention purge par HORODATAGE DE NOM, jamais un fichier au nom inconnu (fail-closed)', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'user-core-retention-'));
    const now = new Date('2026-07-30T12:00:00Z');
    // Trois âges : au-delà de R, dedans, et un intrus au nom illisible.
    await writeFile(join(dir, 'user-core-20260701T000000Z.dump'), 'vieux');
    await writeFile(join(dir, 'user-core-20260729T000000Z.dump'), 'recent');
    await writeFile(join(dir, 'note-intruse.txt'), 'jamais touchée');

    const report = await runBackup({
      targetDir: dir,
      retentionDays: 7, // plancher de TEST — la valeur réelle de R appartient à Kevin (§3.11)
      dumpCommand: process.platform === 'win32' ? ['cmd', '/c', 'echo contenu'] : ['printf', 'contenu'],
      now,
    });

    expect(report.pruned).toEqual(['user-core-20260701T000000Z.dump']);
    const remaining = (await readdir(dir)).sort();
    expect(remaining).toEqual(
      [dumpFileName(now), 'note-intruse.txt', 'user-core-20260729T000000Z.dump'].sort(),
    );
    // Le dump du jour existe et n'est pas vide.
    expect((await stat(report.created)).size).toBeGreaterThan(0);
  });

  test('R invalide ou absent → refus (jamais un défaut « raisonnable » déguisé en décision)', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'user-core-r-'));
    await expect(
      runBackup({ targetDir: dir, retentionDays: 0, dumpCommand: ['peu-importe'] }),
    ).rejects.toThrow(/appartient à Kevin/);
    await expect(
      runBackup({ targetDir: dir, retentionDays: 2.5, dumpCommand: ['peu-importe'] }),
    ).rejects.toThrow(/appartient à Kevin/);
  });

  test('LE CYCLE RÉEL : dump → base neuve → migrations identiques → données relues', async () => {
    const tooling = detectTooling();
    const app = new Pool({ connectionString: appUrl() });
    const owner = new Pool({ connectionString: adminUrl() });
    try {
      // Une donnée distinctive AVANT le dump : elle devra se relire après.
      const marker = String(8_990_000_000 + Math.floor(Math.random() * 1_000_000));
      await createAccount(app, marker);

      const dir = await mkdtemp(join(tmpdir(), 'user-core-backup-'));
      const report = await runBackup({
        targetDir: dir,
        retentionDays: 1, // plancher de TEST (§3.11)
        dumpCommand: dumpCommand(tooling),
      });
      expect((await stat(report.created)).size).toBeGreaterThan(0);

      // BASE NEUVE (les CREATE/DROP DATABASE ne vivent pas en transaction).
      psql(tooling, 'user_core', `DROP DATABASE IF EXISTS ${RESTORE_DB} WITH (FORCE)`);
      psql(tooling, 'user_core', `CREATE DATABASE ${RESTORE_DB}`);
      try {
        restoreDump(tooling, report.created);

        // LES MIGRATIONS : mêmes versions, mêmes checksums — pas un compte
        // seul (le piège de l'agrégat), la LISTE entière, comparée.
        const source = await owner.query<{ version: string; checksum: string }>(
          'SELECT version, checksum FROM schema_migrations ORDER BY version',
        );
        const restored = psql(
          tooling,
          RESTORE_DB,
          'SELECT version || \'|\' || checksum FROM schema_migrations ORDER BY version',
        )
          .split('\n')
          .filter((line) => line.length > 0);
        expect(restored).toEqual(source.rows.map((r) => `${r.version}|${r.checksum}`));
        expect(restored.length).toBeGreaterThanOrEqual(25);

        // LES DONNÉES : la ligne semée se RELIT dans la base restaurée.
        const reread = psql(
          tooling,
          RESTORE_DB,
          `SELECT count(*) FROM accounts WHERE public_identifier = '${marker}'`,
        );
        expect(reread).toBe('1');

        // Et les registres font le même poids (comptes de lignes, par table).
        for (const table of ['accounts', 'persons', 'program_grants', 'phone_claims']) {
          const sourceCount = firstRow(
            await owner.query<{ n: string }>(`SELECT count(*) AS n FROM ${table}`),
          ).n;
          expect(psql(tooling, RESTORE_DB, `SELECT count(*) FROM ${table}`)).toBe(sourceCount);
        }
      } finally {
        psql(tooling, 'user_core', `DROP DATABASE IF EXISTS ${RESTORE_DB} WITH (FORCE)`);
      }
    } finally {
      await app.end();
      await owner.end();
    }
  });

  test('un horodatage de nom se relit sans ambiguïté (aller-retour)', () => {
    const now = new Date('2026-07-30T10:15:00Z');
    const name = dumpFileName(now);
    expect(dumpTimestamp(name)?.toISOString()).toBe('2026-07-30T10:15:00.000Z');
    expect(dumpTimestamp('note-intruse.txt')).toBeNull();
  });
});
