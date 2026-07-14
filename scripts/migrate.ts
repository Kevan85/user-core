import 'dotenv/config';
import { createHash } from 'crypto';
import { readdirSync, readFileSync } from 'fs';
import { join } from 'path';
import { Client } from 'pg';

// =============================================================================
// Runner de migrations RAW-SQL-first (patron payment-core).
//
// Règles (CLAUDE.md §3.1) :
//   - Les fichiers db/schema/NNN_*.sql sont LA source du schéma. Aucun ORM ne
//     le possède ni ne le régénère : les triggers, index uniques partiels et
//     REVOKE sont des invariants d'identité qu'un outil génératif effacerait.
//   - CLI standalone (npm run migrate). Le service ne migre JAMAIS au boot.
//   - Convention transactionnelle : un fichier n'inclut PAS de BEGIN/COMMIT —
//     le runner l'enveloppe avec l'enregistrement dans schema_migrations, le
//     tout atomique. Un fichier qui ouvrirait sa propre transaction serait
//     exécuté verbatim, enregistrement HORS transaction (fenêtre non atomique
//     assumée, bootstrap uniquement) : en cas de crash dans cette fenêtre, la
//     ré-application échoue bruyamment et se corrige à la main.
//   - Checksum SHA-256 calculé sur le contenu NORMALISÉ LF (poste Windows
//     autocrlf vs CI Linux : les octets bruts divergent, le contenu logique
//     non). Un fichier déjà appliqué dont le checksum diverge = migration
//     modifiée après coup → refus net.
// =============================================================================

const MIGRATIONS_DIR = join(__dirname, '..', 'db', 'schema');

// Verrou consultatif : deux runners concurrents sur la même base se
// sérialisent. Clé propre à user-core (payment-core utilise 42170001).
const ADVISORY_LOCK_KEY = 52170001;

interface AppliedRow {
  version: string;
  checksum: string;
}

export function normalizeLf(content: string): string {
  return content.replace(/\r\n/g, '\n');
}

export function checksumOf(normalizedContent: string): string {
  return createHash('sha256').update(normalizedContent, 'utf8').digest('hex');
}

// Détecte un fichier qui gère sa propre transaction : premier token significatif
// (hors lignes vides et commentaires --) = BEGIN. Le double-envelopper produirait
// un « BEGIN imbriqué » (warning) dont le COMMIT interne clôturerait la
// transaction du runner — l'enregistrement partirait alors en autocommit.
export function isSelfTransactional(normalizedContent: string): boolean {
  const firstMeaningfulLine = normalizedContent
    .split('\n')
    .map((line) => line.trim())
    .find((line) => line.length > 0 && !line.startsWith('--'));
  return /^BEGIN\b/i.test(firstMeaningfulLine ?? '');
}

// Un numéro de migration ne se réutilise JAMAIS : deux fichiers 007_* seraient
// appliqués dans un ordre dépendant du système de fichiers.
export function assertUniquePrefixes(files: string[]): void {
  const seenPrefixes = new Set<string>();
  for (const file of files) {
    const prefix = file.slice(0, 3);
    if (seenPrefixes.has(prefix)) {
      throw new Error(`Numéro de migration dupliqué : ${prefix} (${file})`);
    }
    seenPrefixes.add(prefix);
  }
}

function listMigrationFiles(): string[] {
  const files = readdirSync(MIGRATIONS_DIR)
    .filter((f) => /^\d{3}_.+\.sql$/.test(f))
    .sort();
  assertUniquePrefixes(files);
  return files;
}

export async function runMigrations(connectionString: string): Promise<void> {
  const client = new Client({ connectionString });
  await client.connect();
  try {
    await client.query('SELECT pg_advisory_lock($1)', [ADVISORY_LOCK_KEY]);

    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version    text PRIMARY KEY,
        checksum   text NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);

    const appliedResult = await client.query<AppliedRow>(
      'SELECT version, checksum FROM schema_migrations',
    );
    const applied = new Map(appliedResult.rows.map((r) => [r.version, r.checksum]));

    for (const file of listMigrationFiles()) {
      const normalized = normalizeLf(readFileSync(join(MIGRATIONS_DIR, file), 'utf8'));
      const checksum = checksumOf(normalized);

      const priorChecksum = applied.get(file);
      if (priorChecksum !== undefined) {
        if (priorChecksum !== checksum) {
          throw new Error(
            `${file} a été modifié APRÈS application (checksum ${priorChecksum} → ${checksum}). ` +
              'Une migration appliquée est immuable : corriger par une nouvelle migration.',
          );
        }
        console.log(`= ${file} déjà appliquée, ignorée`);
        continue;
      }

      if (isSelfTransactional(normalized)) {
        // Fenêtre non atomique bootstrap-only (voir en-tête).
        await client.query(normalized);
        await client.query(
          'INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)',
          [file, checksum],
        );
        console.log(`+ ${file} appliquée (auto-transactionnelle : enregistrement hors transaction)`);
      } else {
        try {
          await client.query('BEGIN');
          await client.query(normalized);
          await client.query(
            'INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)',
            [file, checksum],
          );
          await client.query('COMMIT');
          console.log(`+ ${file} appliquée (transaction runner, enregistrement atomique)`);
        } catch (err) {
          await client.query('ROLLBACK');
          throw err;
        }
      }
    }

    console.log('Schéma à jour.');
  } finally {
    // La déconnexion libère le verrou consultatif.
    await client.end();
  }
}

if (require.main === module) {
  // Migrer est un acte d'ADMINISTRATION : URL propriétaire, jamais celle du
  // service (le rôle bridé n'a pas le droit de toucher au schéma — et c'est
  // exactement le but).
  const connectionString = process.env.DATABASE_ADMIN_URL;
  if (!connectionString) {
    console.error('DATABASE_ADMIN_URL manquant (voir .env.example)');
    process.exit(1);
  }
  runMigrations(connectionString).catch((err: unknown) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  });
}
