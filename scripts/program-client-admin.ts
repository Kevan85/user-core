import 'dotenv/config';
import { createPublicKey, randomBytes } from 'crypto';
import { Pool } from 'pg';

// =============================================================================
// Administration des identités clientes des programmes (LOT 4, migration 010).
//
// Acte d'ADMINISTRATION : URL propriétaire, jamais celle du service — le rôle
// bridé n'a AUCUN droit d'écriture sur program_clients / program_client_keys,
// et c'est exactement le but (patron scripts/migrate.ts).
//
// AUCUN SECRET ICI : le programme génère sa paire Ed25519 chez lui et ne nous
// transmet que la clé PUBLIQUE (SPKI DER base64). Nous n'avons jamais de quoi
// signer à sa place — il n'y a donc rien à protéger, rien à afficher « une
// seule fois », rien à faire tourner en urgence si ce script fuit.
//
// Usage :
//   npx ts-node scripts/program-client-admin.ts create <code-programme> <kid> <clé-publique-base64>
//   npx ts-node scripts/program-client-admin.ts rotate-key <client_id> <kid> <clé-publique-base64>
//   npx ts-node scripts/program-client-admin.ts revoke <client_id>
// =============================================================================

// Validation applicative = erreur PROPRE (§3.1). Le mur porteur est le CHECK
// chk_program_client_keys_ed25519_spki de la migration 010 : une clé d'un
// autre algorithme, un PEM ou une clé privée n'entrent pas en base, même si
// cette fonction est contournée.
export function assertEd25519PublicKey(publicKeyBase64: string): void {
  let keyObject;
  try {
    keyObject = createPublicKey({
      key: Buffer.from(publicKeyBase64, 'base64'),
      format: 'der',
      type: 'spki',
    });
  } catch {
    throw new Error('clé publique illisible : SPKI DER en base64 attendu');
  }
  if (keyObject.asymmetricKeyType !== 'ed25519') {
    throw new Error(`clé publique Ed25519 exigée, reçu ${keyObject.asymmetricKeyType ?? 'inconnu'}`);
  }
}

export function generateClientId(): string {
  return `pc_${randomBytes(16).toString('hex')}`;
}

export interface RegisteredClient {
  clientId: string;
}

/** Enregistrer une identité cliente + sa première clé, atomiquement. */
export async function registerProgramClient(
  pool: Pool,
  programCode: string,
  kid: string,
  publicKeyBase64: string,
): Promise<RegisteredClient> {
  assertEd25519PublicKey(publicKeyBase64);
  const clientId = generateClientId();

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const program = await client.query<{ id: string }>(
      "SELECT id FROM programs WHERE code = $1 AND status = 'ACTIVE'",
      [programCode],
    );
    const programId = program.rows[0]?.id;
    if (programId === undefined) {
      throw new Error(`programme « ${programCode} » inconnu ou retiré du catalogue`);
    }
    const inserted = await client.query<{ id: string }>(
      'INSERT INTO program_clients (program_id, client_id) VALUES ($1, $2) RETURNING id',
      [programId, clientId],
    );
    const programClientId = inserted.rows[0]?.id;
    if (programClientId === undefined) {
      throw new Error('enregistrement du client : aucune ligne rendue');
    }
    await client.query(
      'INSERT INTO program_client_keys (program_client_id, kid, public_key) VALUES ($1, $2, $3)',
      [programClientId, kid, publicKeyBase64],
    );
    await client.query('COMMIT');
    return { clientId };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Rotation = NOUVELLE ligne (patron 003) : l'ancienne clé ACTIVE passe
 * REVOKED, la neuve naît — atomiquement. L'index unique partiel garantit
 * qu'à aucun instant deux clés ne vérifient pour le même client.
 */
export async function rotateProgramClientKey(
  pool: Pool,
  clientId: string,
  kid: string,
  publicKeyBase64: string,
): Promise<void> {
  assertEd25519PublicKey(publicKeyBase64);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const found = await client.query<{ id: string }>(
      "SELECT id FROM program_clients WHERE client_id = $1 AND status = 'ACTIVE' FOR UPDATE",
      [clientId],
    );
    const programClientId = found.rows[0]?.id;
    if (programClientId === undefined) {
      throw new Error('client inconnu ou révoqué');
    }
    await client.query(
      `UPDATE program_client_keys SET status = 'REVOKED'
        WHERE program_client_id = $1 AND status = 'ACTIVE'`,
      [programClientId],
    );
    await client.query(
      'INSERT INTO program_client_keys (program_client_id, kid, public_key) VALUES ($1, $2, $3)',
      [programClientId, kid, publicKeyBase64],
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Révoquer une identité cliente : UNE écriture — la cascade de la base (010)
 * éteint toutes ses clés. Un programme compromis se coupe ici, sans toucher
 * aux autres.
 */
export async function revokeProgramClient(pool: Pool, clientId: string): Promise<void> {
  const result = await pool.query(
    `UPDATE program_clients SET status = 'REVOKED'
      WHERE client_id = $1 AND status = 'ACTIVE'`,
    [clientId],
  );
  if (result.rowCount === 0) {
    throw new Error('client inconnu ou déjà révoqué');
  }
}

async function main(): Promise<void> {
  const connectionString = process.env.DATABASE_ADMIN_URL;
  if (!connectionString) {
    throw new Error('DATABASE_ADMIN_URL manquant (voir .env.example)');
  }
  const pool = new Pool({ connectionString });
  const [command, ...args] = process.argv.slice(2);
  try {
    switch (command) {
      case 'create': {
        const [programCode, kid, publicKeyBase64] = args;
        if (!programCode || !kid || !publicKeyBase64) {
          throw new Error('usage : create <code-programme> <kid> <clé-publique-base64>');
        }
        const { clientId } = await registerProgramClient(pool, programCode, kid, publicKeyBase64);
        console.log(`client enregistré : ${clientId}`);
        break;
      }
      case 'rotate-key': {
        const [clientId, kid, publicKeyBase64] = args;
        if (!clientId || !kid || !publicKeyBase64) {
          throw new Error('usage : rotate-key <client_id> <kid> <clé-publique-base64>');
        }
        await rotateProgramClientKey(pool, clientId, kid, publicKeyBase64);
        console.log('clé tournée : l\'ancienne est révoquée, la neuve est active');
        break;
      }
      case 'revoke': {
        const [clientId] = args;
        if (!clientId) {
          throw new Error('usage : revoke <client_id>');
        }
        await revokeProgramClient(pool, clientId);
        console.log('client révoqué : toutes ses clés sont éteintes (cascade en base)');
        break;
      }
      default:
        throw new Error('commande attendue : create | rotate-key | revoke');
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
