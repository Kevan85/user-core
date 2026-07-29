import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { DependentAccessService } from '../../src/programs/dependent-access.service';
import { assembleReferenceKeyring } from '../../src/programs/reference-hmac';
import type { ProgramOperationsConfig } from '../../src/programs/program-operations-config';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';
import { fullKeyringEnv } from '../helpers/keyring-env';

/**
 * 024 (étape 4d) — L'IDEMPOTENCE TRAVERSE LA ROTATION du trousseau des
 * références : le re-clic d'une requête ancienne, rejoué APRÈS la bascule
 * vers une clé neuve, reconnaît sa référence — jamais une deuxième fiche
 * d'enfant. Deux services, deux assemblages sur les MÊMES matériaux : une
 * vraie rotation, pas un artefact de test.
 */
const R1 = randomBytes(32).toString('base64');
const R2 = randomBytes(32).toString('base64');

const crypto = assembleCryptoFromEnv(fullKeyringEnv());
const referencesBefore = assembleReferenceKeyring(
  fullKeyringEnv({
    USER_CORE_REF_HMAC_KEYS: JSON.stringify({ R1 }),
    USER_CORE_REF_HMAC_ACTIVE_KEY_ID: 'R1',
  }),
);
const referencesAfter = assembleReferenceKeyring(
  fullKeyringEnv({
    USER_CORE_REF_HMAC_KEYS: JSON.stringify({ R1, R2 }),
    USER_CORE_REF_HMAC_ACTIVE_KEY_ID: 'R2',
  }),
);

const YEAR = new Date().getUTCFullYear();

function config(): ProgramOperationsConfig {
  return {
    dependentInvitationTtlSeconds: 3600,
    inviteClientCap: 1000,
    inviteClientCapWindowSeconds: 3600,
    inviteLineCap: 1000,
    inviteLineCapWindowSeconds: 3600,
  };
}

const DEPENDENT = {
  nameComponents: ['Composante'],
  displayName: 'Ayant Droit De Rotation',
  birthDate: `${YEAR - 9}-06-15`,
};

describe('024 — le re-clic traverse la rotation des références', () => {
  let app: Pool;
  let owner: Pool;
  let programId: string;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    await truncateTables(
      owner,
      'program_invitation_dependents',
      'program_idempotency_keys',
      'program_invitations',
      'program_grants',
      'person_responsibilities',
      'programs',
      'accounts',
      'persons',
    );
    programId = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO programs (code, label, access_mode)
         VALUES ('prog-rotation-ref', 'P', 'GRANTED') RETURNING id`,
      ),
    ).id;
  });

  afterAll(async () => {
    await app.end();
    await owner.end();
  });

  test('clic sous R1, rotation vers R2, re-clic de la MÊME référence → même fiche, jamais une deuxième', async () => {
    const before = new DependentAccessService(app, crypto, referencesBefore, config());
    const first = await before.open(programId, 'REF-TRAVERSE-001', DEPENDENT, '+8801700000201');
    if (first.outcome !== 'ACCEPTED') {
      throw new Error(`ACCEPTED attendu, reçu ${first.outcome}`);
    }

    // La rotation est un redéploiement : nouveau service, R2 signe, R1 lisible.
    const after = new DependentAccessService(app, crypto, referencesAfter, config());
    const replay = await after.open(programId, 'REF-TRAVERSE-001', DEPENDENT, '+8801700000201');
    if (replay.outcome !== 'ACCEPTED') {
      throw new Error(`ACCEPTED attendu, reçu ${replay.outcome}`);
    }
    // Le service rend la MÊME forme au rejeu (délibéré) : la preuve est au
    // REGISTRE — même identifiant, UNE ligne d'idempotence, UNE personne.
    expect(replay.dependentIdentifier).toBe(first.dependentIdentifier);
    const keys = await owner.query('SELECT 1 FROM program_idempotency_keys WHERE program_id = $1', [
      programId,
    ]);
    expect(keys.rows).toHaveLength(1);
    const persons = await owner.query('SELECT 1 FROM persons p WHERE p.public_identifier = $1', [
      first.dependentIdentifier,
    ]);
    expect(persons.rows).toHaveLength(1);
  });

  test('une référence NEUVE après rotation ouvre normalement — et s\'écrit sous R2', async () => {
    const after = new DependentAccessService(app, crypto, referencesAfter, config());
    const opened = await after.open(programId, 'REF-NEUVE-002', DEPENDENT, '+8801700000202');
    if (opened.outcome !== 'ACCEPTED') {
      throw new Error(`ACCEPTED attendu, reçu ${opened.outcome}`);
    }
    const written = await owner.query<{ hmac_key_id: string }>(
      'SELECT hmac_key_id FROM program_idempotency_keys WHERE program_id = $1',
      [programId],
    );
    expect(written.rows.map((r) => r.hmac_key_id)).toContain('R2');
  });

  test('fail-closed : des tableaux de recherche difformes ou sans la paire active → P0111', async () => {
    await expect(
      app.query(
        `SELECT * FROM open_dependent_access($1, '9999999901', $2, 'blob', 'E1', 2016,
           'hmac-ligne', 'H1', 'hmac-actif', 'R2',
           ARRAY['hmac-actif'], ARRAY['R2','R1'],
           3600, 1000, 3600, 1000, 3600)`,
        [programId, randomBytes(32)],
      ),
    ).rejects.toMatchObject({ code: 'P0111' });
    await expect(
      app.query(
        `SELECT * FROM open_dependent_access($1, '9999999902', $2, 'blob', 'E1', 2016,
           'hmac-ligne', 'H1', 'hmac-actif', 'R2',
           ARRAY['autre-hmac'], ARRAY['R1'],
           3600, 1000, 3600, 1000, 3600)`,
        [programId, randomBytes(32)],
      ),
    ).rejects.toMatchObject({ code: 'P0111' });
  });
});
