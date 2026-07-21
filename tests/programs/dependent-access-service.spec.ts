import { randomBytes } from 'crypto';
import { Pool } from 'pg';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { DependentAccessService } from '../../src/programs/dependent-access.service';
import { assembleReferenceKeyring } from '../../src/programs/reference-hmac';
import type { ProgramOperationsConfig } from '../../src/programs/program-operations-config';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// LE CLIC par le service réel, contre la base réelle : la traduction des
// verdicts de 021, le retry d'identifiant, et LA règle de ce fichier —
// ZÉRO log, parce que le payload porte identité, numéro et référence en clair.
const crypto = assembleCryptoFromEnv({
  USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
  USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
  USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
  USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
});
const references = assembleReferenceKeyring({
  USER_CORE_REF_HMAC_KEYS: JSON.stringify({ R1: randomBytes(32).toString('base64') }),
  USER_CORE_REF_HMAC_ACTIVE_KEY_ID: 'R1',
});

const YEAR = new Date().getUTCFullYear();

function config(overrides: Partial<ProgramOperationsConfig> = {}): ProgramOperationsConfig {
  return {
    dependentInvitationTtlSeconds: 3600,
    inviteClientCap: 1000,
    inviteClientCapWindowSeconds: 3600,
    inviteLineCap: 1000,
    inviteLineCapWindowSeconds: 3600,
    ...overrides,
  };
}

function dependent(birthYear: number): {
  nameComponents: string[];
  displayName: string;
  birthDate: string;
} {
  return {
    nameComponents: ['Composante', 'Autre'],
    displayName: 'Ayant Droit De Test',
    birthDate: `${birthYear}-06-15`,
  };
}

describe('le clic /v1 — DependentAccessService (étape 3)', () => {
  let app: Pool;
  let owner: Pool;
  let service: DependentAccessService;
  let seq = 0;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    service = new DependentAccessService(app, crypto, references, config());
    await truncateTables(
      owner,
      'program_invitation_dependents',
      'program_idempotency_keys',
      'program_invitation_refusals',
      'program_invitations',
      'program_grants',
      'programs',
      'persons',
    );
  });

  afterAll(async () => {
    await app.end();
    await owner.end();
  });

  async function grantedProgram(): Promise<string> {
    seq += 1;
    return firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO programs (code, label, access_mode) VALUES ($1, 'P', 'GRANTED') RETURNING id`,
        [`prog-svc-${seq}`],
      ),
    ).id;
  }

  test('nominal : ACCEPTED + identifiant — et AUCUN log (l\'absence se prouve en COMPTANT les appels)', async () => {
    const programId = await grantedProgram();
    const spies = [
      jest.spyOn(console, 'log'),
      jest.spyOn(console, 'error'),
      jest.spyOn(console, 'warn'),
      jest.spyOn(console, 'info'),
    ];
    try {
      const done = await service.open(programId, 'ref-nominal', dependent(YEAR - 9), '+243850000001');
      if (done.outcome !== 'ACCEPTED') throw new Error(`ACCEPTED attendu, reçu ${done.outcome}`);
      expect(done.dependentIdentifier).toMatch(/^[1-9][0-9]{9}$/);

      // Les chemins d'erreur non plus ne journalisent rien.
      expect((await service.open(programId, 'ref-nominal-2', dependent(YEAR - 9), 'pas-un-numero')).outcome).toBe('INVALID_PHONE');
      expect(
        (await service.open(programId, 'ref-nominal-3', { nameComponents: [], displayName: 'X', birthDate: 'n/a' }, '+243850000001')).outcome,
      ).toBe('INVALID_IDENTITY');

      for (const spy of spies) {
        expect(spy).toHaveBeenCalledTimes(0);
      }
    } finally {
      for (const spy of spies) {
        spy.mockRestore();
      }
    }
  });

  test('le rejeu rend la MÊME forme que la première fois : identifiant identique, indiscernable', async () => {
    const programId = await grantedProgram();
    const first = await service.open(programId, 'ref-rejeu', dependent(YEAR - 10), '+243850000002');
    const replay = await service.open(programId, 'ref-rejeu', dependent(YEAR - 10), '+243850000002');
    if (first.outcome !== 'ACCEPTED' || replay.outcome !== 'ACCEPTED') {
      throw new Error('ACCEPTED attendu deux fois');
    }
    expect(replay.dependentIdentifier).toBe(first.dependentIdentifier);
  });

  test('les verdicts de la base traduits : OF_AGE, NOT_GRANTED_MODE, THROTTLED (plafond client)', async () => {
    const programId = await grantedProgram();
    expect((await service.open(programId, 'ref-age', dependent(YEAR - 40), '+243850000003')).outcome).toBe('OF_AGE');

    seq += 1;
    const selfService = firstRow(
      await owner.query<{ id: string }>(
        `INSERT INTO programs (code, label, access_mode) VALUES ($1, 'P', 'SELF_SERVICE') RETURNING id`,
        [`prog-svc-${seq}`],
      ),
    ).id;
    expect((await service.open(selfService, 'ref-mode', dependent(YEAR - 9), '+243850000003')).outcome).toBe('NOT_GRANTED_MODE');

    // Plafond client 1 : la première invitation le consomme, la deuxième
    // (autre ligne, autre référence) est refusée franc.
    const capped = new DependentAccessService(app, crypto, references, config({ inviteClientCap: 1 }));
    const cappedProgram = await grantedProgram();
    expect((await capped.open(cappedProgram, 'ref-cap-1', dependent(YEAR - 9), '+243850000004')).outcome).toBe('ACCEPTED');
    expect((await capped.open(cappedProgram, 'ref-cap-2', dependent(YEAR - 9), '+243850000005')).outcome).toBe('THROTTLED');
  });

  test('collision d\'identifiant : le service RETIRE — même patron que l\'émancipation', async () => {
    const programId = await grantedProgram();
    const taken = await service.open(programId, 'ref-pris', dependent(YEAR - 9), '+243850000006');
    if (taken.outcome !== 'ACCEPTED') throw new Error('ACCEPTED attendu');

    let draws = 0;
    const colliding = new DependentAccessService(app, crypto, references, config(), () => {
      draws += 1;
      return draws === 1 ? taken.dependentIdentifier : String(7_600_000_000 + draws);
    });
    const done = await colliding.open(programId, 'ref-retire', dependent(YEAR - 9), '+243850000007');
    if (done.outcome !== 'ACCEPTED') throw new Error(`ACCEPTED attendu, reçu ${done.outcome}`);
    expect(draws).toBe(2);
    expect(done.dependentIdentifier).not.toBe(taken.dependentIdentifier);
  });
});
