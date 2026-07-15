import { generateKeyPairSync } from 'crypto';
import { Pool } from 'pg';
import {
  assertEd25519PublicKey,
  generateClientId,
  registerProgramClient,
  revokeProgramClient,
  rotateProgramClientKey,
} from '../../scripts/program-client-admin';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// Invariants de la migration 010, prouvés SOUS LE RÔLE BRIDÉ et sous OWNER
// (CLAUDE.md §5) : les GRANT/REVOKE d'un côté, les triggers de l'autre — la
// ceinture au-delà des bretelles.
describe('program_clients / program_client_keys — invariants en base', () => {
  let app: Pool;
  let owner: Pool;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
  });

  beforeEach(async () => {
    await truncateTables(owner, 'program_client_keys', 'program_clients', 'programs');
  });

  afterAll(async () => {
    await truncateTables(owner, 'program_client_keys', 'program_clients', 'programs');
    await app.end();
    await owner.end();
  });

  function publicKeyB64(): string {
    return generateKeyPairSync('ed25519')
      .publicKey.export({ format: 'der', type: 'spki' })
      .toString('base64');
  }

  async function insertProgram(code: string): Promise<string> {
    const r = await owner.query<{ id: string }>(
      "INSERT INTO programs (code, label, access_mode) VALUES ($1, $1, 'GRANTED') RETURNING id",
      [code],
    );
    return firstRow(r).id;
  }

  async function clientRow(clientId: string): Promise<{ id: string; status: string }> {
    return firstRow(
      await owner.query<{ id: string; status: string }>(
        'SELECT id, status FROM program_clients WHERE client_id = $1',
        [clientId],
      ),
    );
  }

  // ---------------------------------------------------------------------------
  // L'enregistrement nominal (outillage d'administration, sous owner)
  // ---------------------------------------------------------------------------

  test('registerProgramClient → client ACTIVE + clé ACTIVE, atomiquement', async () => {
    await insertProgram('prog-a');
    const { clientId } = await registerProgramClient(owner, 'prog-a', 'K1', publicKeyB64());
    expect(clientId).toMatch(/^pc_[a-f0-9]{32}$/);

    const client = await clientRow(clientId);
    expect(client.status).toBe('ACTIVE');

    const keys = await owner.query<{ status: string; kid: string }>(
      'SELECT status, kid FROM program_client_keys WHERE program_client_id = $1',
      [client.id],
    );
    expect(keys.rows.length).toBe(1);
    expect(firstRow(keys)).toEqual({ status: 'ACTIVE', kid: 'K1' });
  });

  test('programme inconnu ou retiré → erreur propre, AUCUNE ligne créée', async () => {
    await expect(
      registerProgramClient(owner, 'prog-fantome', 'K1', publicKeyB64()),
    ).rejects.toThrow(/inconnu ou retiré/);
    const count = firstRow(
      await owner.query<{ n: string }>('SELECT count(*) AS n FROM program_clients'),
    );
    expect(Number(count.n)).toBe(0);
  });

  test('un client ne naît pas sous un programme RETIRED (P0108, sous owner)', async () => {
    const programId = await insertProgram('prog-b');
    await owner.query(
      "UPDATE programs SET status = 'RETIRED', retired_at = now() WHERE id = $1",
      [programId],
    );
    await expect(
      owner.query('INSERT INTO program_clients (program_id, client_id) VALUES ($1, $2)', [
        programId,
        generateClientId(),
      ]),
    ).rejects.toMatchObject({ code: 'P0108' });
  });

  test('recouvrement de compromission : DEUX clients ACTIFS coexistent, puis l\'ancien tombe', async () => {
    // La clé du programme fuite : identité neuve ÉMISE PENDANT que l'ancienne
    // vit encore (le programme bascule sans coupure), puis l'ancienne se
    // révoque. Un « au plus un actif » interdirait ce recouvrement.
    await insertProgram('prog-c');
    const compromised = await registerProgramClient(owner, 'prog-c', 'K1', publicKeyB64());
    const replacement = await registerProgramClient(owner, 'prog-c', 'K1', publicKeyB64());

    const active = await owner.query(
      "SELECT client_id FROM program_clients WHERE status = 'ACTIVE'",
    );
    expect(active.rows).toHaveLength(2);

    await revokeProgramClient(owner, compromised.clientId);
    const after = await owner.query<{ client_id: string }>(
      "SELECT client_id FROM program_clients WHERE status = 'ACTIVE'",
    );
    expect(after.rows).toHaveLength(1);
    expect(after.rows[0]?.client_id).toBe(replacement.clientId);
  });

  test('révoquer le client puis en enregistrer un neuf → permis (la ligne morte reste)', async () => {
    await insertProgram('prog-d');
    const first = await registerProgramClient(owner, 'prog-d', 'K1', publicKeyB64());
    await revokeProgramClient(owner, first.clientId);
    const second = await registerProgramClient(owner, 'prog-d', 'K1', publicKeyB64());
    expect(second.clientId).not.toBe(first.clientId);
    const count = firstRow(
      await owner.query<{ n: string }>('SELECT count(*) AS n FROM program_clients'),
    );
    expect(Number(count.n)).toBe(2);
  });

  // ---------------------------------------------------------------------------
  // La forme des colonnes : le faux n'entre pas
  // ---------------------------------------------------------------------------

  test('client_id hors forme → refus CHECK (sous owner)', async () => {
    const programId = await insertProgram('prog-e');
    await expect(
      owner.query("INSERT INTO program_clients (program_id, client_id) VALUES ($1, 'scolaria-prod')", [
        programId,
      ]),
    ).rejects.toThrow(/chk_program_clients_client_id_shape/);
  });

  test('clé privée PKCS8, PEM ou non-Ed25519 → NON REPRÉSENTABLES (CHECK SPKI)', async () => {
    const programId = await insertProgram('prog-f');
    const inserted = await owner.query<{ id: string }>(
      'INSERT INTO program_clients (program_id, client_id) VALUES ($1, $2) RETURNING id',
      [programId, generateClientId()],
    );
    const programClientId = firstRow(inserted).id;

    // Une clé PRIVÉE Ed25519 (PKCS8) : en-tête DER différent → refusée.
    const privatePkcs8 = generateKeyPairSync('ed25519')
      .privateKey.export({ format: 'der', type: 'pkcs8' })
      .toString('base64');
    // Une clé RSA publique : autre algorithme, autre en-tête → refusée.
    const rsaSpki = generateKeyPairSync('rsa', { modulusLength: 2048 })
      .publicKey.export({ format: 'der', type: 'spki' })
      .toString('base64');

    for (const bad of [privatePkcs8, rsaSpki, 'pas-du-der', '']) {
      await expect(
        owner.query(
          "INSERT INTO program_client_keys (program_client_id, kid, public_key) VALUES ($1, 'K1', $2)",
          [programClientId, bad],
        ),
      ).rejects.toThrow(/chk_program_client_keys_ed25519_spki|violates check constraint/);
    }
  });

  test('assertEd25519PublicKey — la façade applicative refuse les mêmes formes', () => {
    const privatePkcs8 = generateKeyPairSync('ed25519')
      .privateKey.export({ format: 'der', type: 'pkcs8' })
      .toString('base64');
    expect(() => assertEd25519PublicKey(privatePkcs8)).toThrow();
    expect(() => assertEd25519PublicKey('pas-du-der')).toThrow(/SPKI DER/);
    expect(() => assertEd25519PublicKey(publicKeyB64())).not.toThrow();
  });

  // ---------------------------------------------------------------------------
  // Le rôle applicatif n'écrit RIEN (acte d'administration)
  // ---------------------------------------------------------------------------

  test('INSERT / UPDATE / DELETE / TRUNCATE sous rôle bridé → permission denied', async () => {
    await insertProgram('prog-g');
    const { clientId } = await registerProgramClient(owner, 'prog-g', 'K1', publicKeyB64());
    const client = await clientRow(clientId);

    await expect(
      app.query('INSERT INTO program_clients (program_id, client_id) VALUES ($1, $2)', [
        client.id,
        generateClientId(),
      ]),
    ).rejects.toThrow(/permission denied/);
    await expect(
      app.query("UPDATE program_clients SET status = 'REVOKED' WHERE id = $1", [client.id]),
    ).rejects.toThrow(/permission denied/);
    await expect(app.query('DELETE FROM program_clients WHERE id = $1', [client.id])).rejects.toThrow(
      /permission denied/,
    );
    await expect(app.query('TRUNCATE program_clients CASCADE')).rejects.toThrow(/permission denied/);

    await expect(
      app.query(
        "INSERT INTO program_client_keys (program_client_id, kid, public_key) VALUES ($1, 'K9', $2)",
        [client.id, publicKeyB64()],
      ),
    ).rejects.toThrow(/permission denied/);
    await expect(
      app.query("UPDATE program_client_keys SET status = 'REVOKED' WHERE program_client_id = $1", [
        client.id,
      ]),
    ).rejects.toThrow(/permission denied/);
  });

  test('le rôle bridé LIT les clés publiques (il en a besoin pour vérifier)', async () => {
    await insertProgram('prog-h');
    const { clientId } = await registerProgramClient(owner, 'prog-h', 'K1', publicKeyB64());
    const rows = await app.query(
      `SELECT k.kid, k.public_key FROM program_client_keys k
        JOIN program_clients c ON c.id = k.program_client_id
       WHERE c.client_id = $1 AND k.status = 'ACTIVE' AND c.status = 'ACTIVE'`,
      [clientId],
    );
    expect(rows.rows.length).toBe(1);
  });

  // ---------------------------------------------------------------------------
  // Les triggers tiennent sous OWNER (au-delà des droits)
  // ---------------------------------------------------------------------------

  test('DELETE sous owner → suppression interdite (P0107)', async () => {
    await insertProgram('prog-i');
    const { clientId } = await registerProgramClient(owner, 'prog-i', 'K1', publicKeyB64());
    const client = await clientRow(clientId);
    await expect(owner.query('DELETE FROM program_clients WHERE id = $1', [client.id])).rejects.toMatchObject(
      { code: 'P0107' },
    );
    await expect(
      owner.query('DELETE FROM program_client_keys WHERE program_client_id = $1', [client.id]),
    ).rejects.toMatchObject({ code: 'P0107' });
  });

  test('identité immuable : client_id, program_id, public_key, kid (P0101, sous owner)', async () => {
    await insertProgram('prog-j');
    const { clientId } = await registerProgramClient(owner, 'prog-j', 'K1', publicKeyB64());
    const client = await clientRow(clientId);

    await expect(
      owner.query('UPDATE program_clients SET client_id = $2 WHERE id = $1', [
        client.id,
        generateClientId(),
      ]),
    ).rejects.toMatchObject({ code: 'P0101' });
    await expect(
      owner.query('UPDATE program_client_keys SET public_key = $2 WHERE program_client_id = $1', [
        client.id,
        publicKeyB64(),
      ]),
    ).rejects.toMatchObject({ code: 'P0101' });
    await expect(
      owner.query("UPDATE program_client_keys SET kid = 'K2' WHERE program_client_id = $1", [
        client.id,
      ]),
    ).rejects.toMatchObject({ code: 'P0101' });
  });

  test('révocation : la BASE horodate, la ligne se fige, aucun retour (P0103/P0104)', async () => {
    await insertProgram('prog-k');
    const { clientId } = await registerProgramClient(owner, 'prog-k', 'K1', publicKeyB64());
    const client = await clientRow(clientId);

    // Horodatage fantaisiste envoyé avec la révocation → écrasé par now().
    await owner.query(
      "UPDATE program_clients SET status = 'REVOKED', revoked_at = '2019-01-01' WHERE id = $1",
      [client.id],
    );
    const revoked = firstRow(
      await owner.query<{ age_seconds: number }>(
        `SELECT EXTRACT(EPOCH FROM (now() - revoked_at))::float AS age_seconds
           FROM program_clients WHERE id = $1`,
        [client.id],
      ),
    );
    expect(revoked.age_seconds).toBeLessThan(60);

    // Figée : ni résurrection, ni re-datation.
    await expect(
      owner.query("UPDATE program_clients SET status = 'ACTIVE' WHERE id = $1", [client.id]),
    ).rejects.toMatchObject({ code: 'P0103' });
    await expect(
      owner.query("UPDATE program_clients SET revoked_at = '2020-01-01' WHERE id = $1", [client.id]),
    ).rejects.toMatchObject({ code: 'P0103' });

    // Re-datation d'une ligne VIVANTE (sans changement de statut) → P0104.
    const other = await registerProgramClient(owner, 'prog-k', 'K1', publicKeyB64());
    const otherRow = await clientRow(other.clientId);
    await expect(
      owner.query("UPDATE program_clients SET revoked_at = '2020-01-01' WHERE id = $1", [otherRow.id]),
    ).rejects.toMatchObject({ code: 'P0104' });
  });

  // ---------------------------------------------------------------------------
  // La cascade et la rotation
  // ---------------------------------------------------------------------------

  test('révoquer le client éteint TOUTES ses clés — une écriture (cascade C1)', async () => {
    await insertProgram('prog-l');
    const { clientId } = await registerProgramClient(owner, 'prog-l', 'K1', publicKeyB64());
    await revokeProgramClient(owner, clientId);

    const client = await clientRow(clientId);
    expect(client.status).toBe('REVOKED');
    const keys = await owner.query<{ status: string }>(
      'SELECT status FROM program_client_keys WHERE program_client_id = $1',
      [client.id],
    );
    // Nombre de lignes ET statut (piège « sum = 0 », CLAUDE.md §5).
    expect(keys.rows.length).toBe(1);
    expect(keys.rows.every((k) => k.status === 'REVOKED')).toBe(true);
  });

  test('aucune clé ne naît sous un client révoqué (P0108, sous owner)', async () => {
    await insertProgram('prog-m');
    const { clientId } = await registerProgramClient(owner, 'prog-m', 'K1', publicKeyB64());
    await revokeProgramClient(owner, clientId);
    const client = await clientRow(clientId);
    await expect(
      owner.query(
        "INSERT INTO program_client_keys (program_client_id, kid, public_key) VALUES ($1, 'K2', $2)",
        [client.id, publicKeyB64()],
      ),
    ).rejects.toMatchObject({ code: 'P0108' });
  });

  test('deux clés ACTIVE pour un même client → non représentable (index partiel)', async () => {
    await insertProgram('prog-n');
    const { clientId } = await registerProgramClient(owner, 'prog-n', 'K1', publicKeyB64());
    const client = await clientRow(clientId);
    await expect(
      owner.query(
        "INSERT INTO program_client_keys (program_client_id, kid, public_key) VALUES ($1, 'K2', $2)",
        [client.id, publicKeyB64()],
      ),
    ).rejects.toThrow(/uq_program_client_keys_active/);
  });

  test('rotation = nouvelle ligne : l\'ancienne REVOKED, la neuve ACTIVE, l\'histoire reste', async () => {
    await insertProgram('prog-o');
    const { clientId } = await registerProgramClient(owner, 'prog-o', 'K1', publicKeyB64());
    await rotateProgramClientKey(owner, clientId, 'K2', publicKeyB64());

    const client = await clientRow(clientId);
    const keys = await owner.query<{ kid: string; status: string }>(
      'SELECT kid, status FROM program_client_keys WHERE program_client_id = $1 ORDER BY created_at',
      [client.id],
    );
    expect(keys.rows.length).toBe(2);
    expect(keys.rows[0]).toEqual({ kid: 'K1', status: 'REVOKED' });
    expect(keys.rows[1]).toEqual({ kid: 'K2', status: 'ACTIVE' });
  });

  test('rotation sur un client révoqué → refus (le client est mort, ses clés aussi)', async () => {
    await insertProgram('prog-p');
    const { clientId } = await registerProgramClient(owner, 'prog-p', 'K1', publicKeyB64());
    await revokeProgramClient(owner, clientId);
    await expect(rotateProgramClientKey(owner, clientId, 'K2', publicKeyB64())).rejects.toThrow(
      /inconnu ou révoqué/,
    );
    await expect(revokeProgramClient(owner, clientId)).rejects.toThrow(/inconnu ou déjà révoqué/);
  });
});
