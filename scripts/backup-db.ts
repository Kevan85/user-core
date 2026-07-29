import 'dotenv/config';
import { spawn } from 'child_process';
import { createWriteStream } from 'fs';
import { mkdir, readdir, stat, unlink } from 'fs/promises';
import { join } from 'path';

/**
 * SAUVEGARDE + RÉTENTION PARAMÉTRÉE (LOT prod, étape 6).
 *
 * R (BACKUP_RETENTION_DAYS) est une INCONNUE DE TERRAIN qui appartient à
 * Kevin (§3.11) : aucune valeur par défaut ici — un « défaut raisonnable »
 * serait une décision déguisée. Le script REFUSE de courir sans R.
 *
 * R n'est pas un détail d'intendance : c'est la borne de la
 * crypto-destruction. « Effacer une personne » = détruire son sel — mais une
 * sauvegarde antérieure contient encore l'ancien sel : « effacé » veut dire
 * « effacé à J+R ». Sans rétention bornée, la crypto-destruction est un
 * mensonge (docs/ops/SAUVEGARDES.md, et le LOT effacement le dira à Kevin).
 *
 * La rétention s'applique par HORODATAGE DE NOM (jamais le mtime : une copie,
 * un rsync, un antivirus le réécrivent) ; un fichier au nom illisible n'est
 * JAMAIS supprimé (fail-closed : on ne purge que ce qu'on a soi-même nommé).
 */
export interface BackupReport {
  created: string;
  pruned: string[];
}

const DUMP_PREFIX = 'user-core-';
const DUMP_SUFFIX = '.dump';
// user-core-20260730T101500Z.dump
const DUMP_NAME = /^user-core-(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z\.dump$/;

export function dumpFileName(now: Date): string {
  const iso = now.toISOString(); // 2026-07-30T10:15:00.123Z
  const compact = iso.slice(0, 19).replace(/[-:]/g, '');
  return `${DUMP_PREFIX}${compact}Z${DUMP_SUFFIX}`;
}

export function dumpTimestamp(name: string): Date | null {
  const match = DUMP_NAME.exec(name);
  if (match === null) {
    return null;
  }
  const [, y, mo, d, h, mi, s] = match as unknown as [string, ...string[]];
  return new Date(Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s)));
}

function run(command: string[], stdoutFile?: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const [head, ...rest] = command;
    if (head === undefined) {
      reject(new Error('commande vide'));
      return;
    }
    const child = spawn(head, rest, {
      stdio: ['ignore', stdoutFile === undefined ? 'ignore' : 'pipe', 'inherit'],
    });
    if (stdoutFile !== undefined && child.stdout !== null) {
      child.stdout.pipe(createWriteStream(stdoutFile));
    }
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`${head} : sortie ${code}`));
      }
    });
  });
}

export async function runBackup(options: {
  targetDir: string;
  retentionDays: number;
  /** La commande de dump, stdout = le dump (format custom). */
  dumpCommand: string[];
  now?: Date;
}): Promise<BackupReport> {
  const { targetDir, retentionDays, dumpCommand } = options;
  if (!Number.isInteger(retentionDays) || retentionDays < 1) {
    throw new Error(
      `rétention invalide : « ${retentionDays} » — R se compte en jours entiers (≥ 1), et sa ` +
        'valeur réelle appartient à Kevin (§3.11)',
    );
  }
  const now = options.now ?? new Date();
  await mkdir(targetDir, { recursive: true });

  const created = join(targetDir, dumpFileName(now));
  try {
    await run(dumpCommand, created);
  } catch (err) {
    // Jamais un dump partiel qui ressemble à un vrai : on retire, on relance.
    await unlink(created).catch(() => undefined);
    throw err;
  }
  const dumped = await stat(created);
  if (dumped.size === 0) {
    await unlink(created).catch(() => undefined);
    throw new Error('dump vide : la sauvegarde a échoué, rien à conserver');
  }

  const limit = now.getTime() - retentionDays * 86_400_000;
  const pruned: string[] = [];
  for (const name of await readdir(targetDir)) {
    if (name === dumpFileName(now)) {
      continue;
    }
    const stamp = dumpTimestamp(name);
    if (stamp !== null && stamp.getTime() < limit) {
      await unlink(join(targetDir, name));
      pruned.push(name);
    }
  }
  return { created, pruned };
}

async function main(): Promise<void> {
  const adminUrl = process.env.DATABASE_ADMIN_URL;
  const targetDir = process.env.BACKUP_DIR;
  const retentionRaw = process.env.BACKUP_RETENTION_DAYS;
  const missing: string[] = [];
  if (!adminUrl) missing.push('DATABASE_ADMIN_URL');
  if (!targetDir) missing.push('BACKUP_DIR');
  if (!retentionRaw) missing.push('BACKUP_RETENTION_DAYS (R — la valeur appartient à Kevin, §3.11)');
  if (missing.length > 0 || !adminUrl || !targetDir || !retentionRaw) {
    throw new Error(`sauvegarde refusée, variables manquantes :\n- ${missing.join('\n- ')}`);
  }
  const report = await runBackup({
    targetDir,
    retentionDays: Number(retentionRaw),
    dumpCommand: ['pg_dump', '--format=custom', '--dbname', adminUrl],
  });
  console.log(
    `sauvegarde écrite (${report.created}) ; ${report.pruned.length} dump(s) au-delà de R purgé(s)`,
  );
}

if (require.main === module) {
  main().catch((err: unknown) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  });
}
