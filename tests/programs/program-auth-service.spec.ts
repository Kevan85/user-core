import { generateKeyPairSync, randomUUID, sign as ed25519Sign, type KeyObject } from 'crypto';
import { Pool } from 'pg';
import { LocalAuthenticationProvider } from '../../src/auth/local-authentication-provider';
import { LoginThrottle } from '../../src/auth/login-throttle';
import type { ProgramAuthConfig } from '../../src/programs/program-auth-config';
import { ASSERTION_AUDIENCE, ProgramAuthService } from '../../src/programs/program-auth.service';
import { verifyProgramToken } from '../../src/programs/program-token';
import {
  registerProgramClient,
  revokeProgramClient,
  rotateProgramClientKey,
} from '../../scripts/program-client-admin';
import { testAuthAssembly } from '../helpers/auth';
import { adminUrl, appUrl, firstRow, truncateTables } from '../helpers/db';

// L'échange assertion → jeton, SOUS RÔLE BRIDÉ. Les propriétés : l'identité
// se dérive de la clé qui vérifie (annoncer le client d'un autre ne sert à
// rien), le rejeu est bloqué PAR LA BASE (013), tous les refus sont
// indiscernables, et AUCUN jeton ne traverse la frontière compte/programme.
const authConfig = testAuthAssembly();

function programAuthConfig(overrides: Partial<ProgramAuthConfig> = {}): ProgramAuthConfig {
  return {
    tokenTtlSeconds: 900,
    assertionMaxTtlSeconds: 300,
    throttleMaxAttempts: 1000,
    throttleWindowSeconds: 60,
    ...overrides,
  };
}

interface AssertionOptions {
  kid?: string;
  jti?: string;
  exp?: number;
  aud?: string;
  alg?: string;
}

function buildAssertion(
  privateKey: KeyObject,
  clientId: string,
  options: AssertionOptions = {},
): string {
  const header = { alg: options.alg ?? 'EdDSA', typ: 'JWT', kid: options.kid ?? 'K1' };
  const payload = {
    iss: clientId,
    jti: options.jti ?? randomUUID(),
    exp: options.exp ?? Math.floor(Date.now() / 1000) + 60,
    aud: options.aud ?? ASSERTION_AUDIENCE,
  };
  const encode = (v: object): string => Buffer.from(JSON.stringify(v), 'utf8').toString('base64url');
  const signingInput = `${encode(header)}.${encode(payload)}`;
  const signature = ed25519Sign(null, Buffer.from(signingInput, 'utf8'), privateKey);
  return `${signingInput}.${signature.toString('base64url')}`;
}

describe('ProgramAuthService — assertion signée → jeton de programme', () => {
  let app: Pool;
  let owner: Pool;
  let service: ProgramAuthService;

  beforeAll(async () => {
    app = new Pool({ connectionString: appUrl() });
    owner = new Pool({ connectionString: adminUrl() });
    service = new ProgramAuthService(
      app,
      authConfig,
      programAuthConfig(),
      new LoginThrottle(1000, 60),
    );
  });

  beforeEach(async () => {
    await truncateTables(
      owner,
      'program_client_assertions',
      'program_client_keys',
      'program_clients',
      'programs',
    );
  });

  afterAll(async () => {
    await app.end();
    await owner.end();
  });

  interface Fixture {
    clientId: string;
    programId: string;
    privateKey: KeyObject;
    publicKeyB64: string;
  }

  async function newClient(code: string): Promise<Fixture> {
    const programId = firstRow(
      await owner.query<{ id: string }>(
        "INSERT INTO programs (code, label, access_mode) VALUES ($1, $1, 'GRANTED') RETURNING id",
        [code],
      ),
    ).id;
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const publicKeyB64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
    const { clientId } = await registerProgramClient(owner, code, 'K1', publicKeyB64);
    return { clientId, programId, privateKey, publicKeyB64 };
  }

  test('assertion valide → jeton dont le pid EST le programme ; l\'identité vient de la clé', async () => {
    const f = await newClient('prog-token');
    const result = await service.token(buildAssertion(f.privateKey, f.clientId), '10.2.0.1');
    if (result.outcome !== 'OK') throw new Error(`OK attendu, reçu ${result.outcome}`);

    const claims = verifyProgramToken(authConfig, result.accessToken);
    expect(claims).toEqual({ sub: f.clientId, pid: f.programId });
    expect(result.expiresAt.getTime()).toBeGreaterThan(Date.now());
  });

  test('DISJONCTION : un jeton de programme est NUL pour les comptes, et réciproquement', async () => {
    const f = await newClient('prog-frontiere');
    const result = await service.token(buildAssertion(f.privateKey, f.clientId), '10.2.0.2');
    if (result.outcome !== 'OK') throw new Error('OK attendu');

    // Le vérificateur des COMPTES exige sid : jeton de programme → null.
    const accountVerifier = new LocalAuthenticationProvider(authConfig);
    expect(await accountVerifier.verifyAccessToken(result.accessToken)).toBeNull();

    // Le vérificateur des PROGRAMMES exige pid + kind : jeton de compte → null.
    const accountToken = await accountVerifier.issueAccessToken({
      sub: randomUUID(),
      sid: randomUUID(),
    });
    expect(verifyProgramToken(authConfig, accountToken.token)).toBeNull();
  });

  test('REJEU : la même assertion ne s\'échange qu\'UNE fois — la base tranche (013)', async () => {
    const f = await newClient('prog-rejeu');
    const assertion = buildAssertion(f.privateKey, f.clientId);
    expect((await service.token(assertion, '10.2.0.3')).outcome).toBe('OK');
    expect((await service.token(assertion, '10.2.0.3')).outcome).toBe('REPLAYED');

    const rows = firstRow(
      await owner.query<{ n: string }>('SELECT count(*) AS n FROM program_client_assertions'),
    );
    expect(Number(rows.n)).toBe(1);
  });

  test('tous les refus sont INDISCERNABLES : forgé, client inconnu, aud étrangère, périmé, trop long, jti difforme, alg étranger', async () => {
    const f = await newClient('prog-refus');
    const intruder = generateKeyPairSync('ed25519').privateKey;
    const nowSeconds = Math.floor(Date.now() / 1000);

    const refusals = await Promise.all([
      // Signé par une AUTRE clé, sous le bon iss/kid : l'identité ne se déclare pas.
      service.token(buildAssertion(intruder, f.clientId), '10.2.0.4'),
      // Client inconnu.
      service.token(buildAssertion(f.privateKey, 'pc_' + '0'.repeat(32)), '10.2.0.4'),
      // Audience d'un autre cœur : jamais échangeable ici.
      service.token(buildAssertion(f.privateKey, f.clientId, { aud: 'autre-service' }), '10.2.0.4'),
      // Périmée.
      service.token(
        buildAssertion(f.privateKey, f.clientId, { exp: nowSeconds - 10 }),
        '10.2.0.4',
      ),
      // Échéance au-delà de la fenêtre admise (pas de jti éternel).
      service.token(
        buildAssertion(f.privateKey, f.clientId, { exp: nowSeconds + 3600 }),
        '10.2.0.4',
      ),
      // jti hors forme.
      service.token(buildAssertion(f.privateKey, f.clientId, { jti: 'x' }), '10.2.0.4'),
      // Algorithme non épinglé.
      service.token(buildAssertion(f.privateKey, f.clientId, { alg: 'HS256' }), '10.2.0.4'),
      // Illisible.
      service.token('pas-un-jws', '10.2.0.4'),
    ]);
    for (const refusal of refusals) {
      expect(refusal).toEqual({ outcome: 'REFUSED' });
    }
    // Aucun refus n'a consommé de jti.
    const rows = firstRow(
      await owner.query<{ n: string }>('SELECT count(*) AS n FROM program_client_assertions'),
    );
    expect(Number(rows.n)).toBe(0);
  });

  test('clé TOURNÉE : l\'ancienne ne signe plus, la neuve signe', async () => {
    const f = await newClient('prog-rotation');
    const next = generateKeyPairSync('ed25519');
    await rotateProgramClientKey(
      owner,
      f.clientId,
      'K2',
      next.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    );

    expect(
      (await service.token(buildAssertion(f.privateKey, f.clientId, { kid: 'K1' }), '10.2.0.5'))
        .outcome,
    ).toBe('REFUSED');
    expect(
      (await service.token(buildAssertion(next.privateKey, f.clientId, { kid: 'K2' }), '10.2.0.5'))
        .outcome,
    ).toBe('OK');
  });

  test('client RÉVOQUÉ : plus aucun jeton — un programme compromis est coupé net', async () => {
    const f = await newClient('prog-coupe');
    await revokeProgramClient(owner, f.clientId);
    expect((await service.token(buildAssertion(f.privateKey, f.clientId), '10.2.0.6')).outcome).toBe(
      'REFUSED',
    );
  });

  test('throttle par IP et par client visé : la 3e tentative tombe', async () => {
    const f = await newClient('prog-throttle');
    const throttled = new ProgramAuthService(
      app,
      authConfig,
      programAuthConfig({ throttleMaxAttempts: 2 }),
      new LoginThrottle(2, 60),
    );
    expect((await throttled.token(buildAssertion(f.privateKey, f.clientId), '10.2.0.7')).outcome).toBe('OK');
    expect((await throttled.token(buildAssertion(f.privateKey, f.clientId), '10.2.0.7')).outcome).toBe('OK');
    expect((await throttled.token(buildAssertion(f.privateKey, f.clientId), '10.2.0.7')).outcome).toBe(
      'THROTTLED',
    );
  });

  test('013 — le registre des jti est append-only, aux deux étages', async () => {
    const f = await newClient('prog-registre');
    const assertion = buildAssertion(f.privateKey, f.clientId);
    expect((await service.token(assertion, '10.2.0.8')).outcome).toBe('OK');

    const row = firstRow(
      await owner.query<{ id: string; program_client_id: string; jti: string }>(
        'SELECT id, program_client_id, jti FROM program_client_assertions',
      ),
    );
    // Doublon sous OWNER → l'unicité tient au-delà des droits.
    await expect(
      owner.query(
        "INSERT INTO program_client_assertions (program_client_id, jti, expires_at) VALUES ($1, $2, now() + interval '1 minute')",
        [row.program_client_id, row.jti],
      ),
    ).rejects.toThrow(/uq_program_client_assertions_jti/);
    // Un jti consommé ne se libère JAMAIS.
    await expect(
      owner.query('DELETE FROM program_client_assertions WHERE id = $1', [row.id]),
    ).rejects.toMatchObject({ code: 'P0107' });
    await expect(
      owner.query("UPDATE program_client_assertions SET jti = 'autre-jti-0001' WHERE id = $1", [
        row.id,
      ]),
    ).rejects.toMatchObject({ code: 'P0101' });
    await expect(
      app.query('DELETE FROM program_client_assertions WHERE id = $1', [row.id]),
    ).rejects.toThrow(/permission denied/);

    // Aucune assertion ne s'enregistre sous un client mort (P0108, owner).
    await revokeProgramClient(owner, f.clientId);
    await expect(
      owner.query(
        "INSERT INTO program_client_assertions (program_client_id, jti, expires_at) VALUES ($1, 'jti-client-mort', now() + interval '1 minute')",
        [row.program_client_id],
      ),
    ).rejects.toMatchObject({ code: 'P0108' });
  });
});
