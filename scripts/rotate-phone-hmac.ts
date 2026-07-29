import 'dotenv/config';
import { Pool } from 'pg';
import { fingerprintUnder } from '../src/crypto/fingerprint';
import { assembleKeyringsFromEnv, type KeyringAssembly } from '../src/crypto/keyring';
import { resolveVerifiedAddress } from '../src/phone/verified-address';

/**
 * ROTATION DE LA CLÉ D'EMPREINTE TÉLÉPHONE — la procédure exceptionnelle
 * (CDC §6.1), exécutée SERVICE ARRÊTÉ (docs/ops/ROTATION.md : la fenêtre
 * d'indisponibilité est structurelle — pendant la rotation, la clé active du
 * service diverge de la référence, et le boot refuse).
 *
 * L'ORDRE EST GARDÉ PAR LA BASE, pas par ce script (mur 025, exigence C1) :
 * la référence ne bascule pas tant qu'une revendication ACTIVE vit sous une
 * autre clé. Un script interrompu laisse une transaction avortée — jamais un
 * état à deux clés.
 *
 * DISCIPLINES TENUES ICI :
 *   · le clair ne s'obtient QUE par le point unique (resolveVerifiedAddress,
 *     motif F) — qui RE-DÉRIVE l'empreinte sous l'ancienne clé et refuse
 *     toute divergence AVANT de re-hacher : on ne re-signe jamais un
 *     mensonge ;
 *   · les trousseaux ne s'assemblent QUE par le point unique (motif H) ;
 *   · DISABLE TRIGGER USER est borné à la transaction et RÉARMÉ dedans — le
 *     filet (pg_trigger.tgenabled = 'O') est vérifié par le test à chaque CI ;
 *   · zéro PII en sortie : des comptes de lignes, jamais un numéro.
 *
 * Ce qui reste sous l'ancienne clé, DÉLIBÉRÉMENT (025 en-tête) : les lignes
 * REVOKED (histoire figée — leur empreinte n'entre plus dans aucune unicité)
 * et les PENDING (elles ne peuvent plus s'activer, P0109 — refus propre).
 */
export interface RotationReport {
  fromKeyId: string;
  toKeyId: string;
  rehashed: number;
  integrityFailures: number;
}

export async function rotatePhoneHmacKey(
  pool: Pool,
  keyrings: KeyringAssembly,
): Promise<RotationReport> {
  const target = keyrings.fingerprint.activeKeyId;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const reference = await client.query<{ hmac_key_id: string }>(
      'SELECT hmac_key_id FROM hmac_key_reference WHERE singleton FOR UPDATE',
    );
    const current = reference.rows[0]?.hmac_key_id;
    if (current === undefined) {
      throw new Error('hmac_key_reference vide : lecture fail-closed, rotation impossible');
    }
    if (current === target) {
      await client.query('ROLLBACK');
      return { fromKeyId: current, toKeyId: target, rehashed: 0, integrityFailures: 0 };
    }

    const claims = await client.query<{ id: string }>(
      `SELECT id FROM phone_claims WHERE status = 'ACTIVE' AND hmac_key_id <> $1 FOR UPDATE`,
      [target],
    );

    // Les triggers d'immuabilité (006/018) protègent le REGISTRE VIVANT ;
    // la rotation est l'acte d'exploitation signé qui les suspend — DANS la
    // transaction, réarmés avant le COMMIT.
    await client.query('ALTER TABLE phone_claims DISABLE TRIGGER USER');

    let rehashed = 0;
    for (const { id } of claims.rows) {
      const resolution = await resolveVerifiedAddress(client, keyrings, id, true);
      if (resolution.outcome !== 'RESOLVED') {
        // Fail-closed : UNE ligne dont l'empreinte et le chiffré divergent
        // suffit à tout arrêter — re-hacher « le reste » masquerait une
        // violation d'intégrité.
        throw new Error(
          `rotation interrompue : intégrité en défaut sur une revendication (claim=${id}) — aucune ligne re-hachée`,
        );
      }
      const next = fingerprintUnder(keyrings.fingerprint, target, resolution.phone);
      if (next === null) {
        throw new Error(`rotation interrompue : clé cible « ${target} » absente du trousseau`);
      }
      await client.query('UPDATE phone_claims SET phone_hmac = $2, hmac_key_id = $3 WHERE id = $1', [
        id,
        next.value,
        target,
      ]);
      rehashed += 1;
    }

    await client.query('ALTER TABLE phone_claims ENABLE TRIGGER USER');

    // LA BASCULE — sous le mur 025 : s'il reste une ACTIVE sous une autre
    // clé, la base refuse (P0115) et la transaction entière tombe.
    await client.query(
      'UPDATE hmac_key_reference SET hmac_key_id = $1, rotated_at = now() WHERE singleton',
      [target],
    );

    await client.query('COMMIT');
    return { fromKeyId: current, toKeyId: target, rehashed, integrityFailures: 0 };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function main(): Promise<void> {
  const adminUrl = process.env.DATABASE_ADMIN_URL;
  if (!adminUrl) {
    throw new Error('DATABASE_ADMIN_URL manquant : la rotation est un acte d\'exploitation (owner)');
  }
  const keyrings = assembleKeyringsFromEnv();
  const pool = new Pool({ connectionString: adminUrl });
  try {
    const report = await rotatePhoneHmacKey(pool, keyrings);
    if (report.fromKeyId === report.toKeyId) {
      console.log(`référence déjà sur « ${report.toKeyId} » : rien à faire`);
    } else {
      console.log(
        `rotation « ${report.fromKeyId} » -> « ${report.toKeyId} » : ${report.rehashed} revendication(s) re-hachée(s)`,
      );
    }
  } finally {
    await pool.end();
  }
}

if (require.main === module) {
  main().catch((err: unknown) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  });
}
