import { assembleAuthFromEnv, MAX_ACCESS_TOKEN_TTL_SECONDS } from '../../src/auth/auth-config';
import { ConfigViolations } from '../../src/bootstrap/assembly';
import { ed25519KeyBase64 } from '../helpers/auth';

function validEnv(): NodeJS.ProcessEnv {
  return {
    AUTH_SIGNING_KEYS: JSON.stringify({ K1: ed25519KeyBase64() }),
    AUTH_ACTIVE_KEY_ID: 'K1',
  };
}

describe('assembleAuthFromEnv (C2, C7)', () => {
  test('C2 — TTL au-delà de 15 min → REFUS de boot (borne dure, pas une config)', () => {
    const env = { ...validEnv(), AUTH_ACCESS_TOKEN_TTL_SECONDS: '1200' };
    expect(() => assembleAuthFromEnv(env)).toThrow(ConfigViolations);
    expect(() => assembleAuthFromEnv(env)).toThrow(/borne dure de 900 s/);
  });

  test('C2 — TTL à exactement la borne (900 s) → accepté', () => {
    const env = { ...validEnv(), AUTH_ACCESS_TOKEN_TTL_SECONDS: String(MAX_ACCESS_TOKEN_TTL_SECONDS) };
    expect(assembleAuthFromEnv(env).accessTokenTtlSeconds).toBe(900);
  });

  test('C7 — les paramètres argon2id viennent de l\'env, avec défauts explicites', () => {
    const defaults = assembleAuthFromEnv(validEnv());
    expect(defaults.argon2).toEqual({ memoryCost: 65536, timeCost: 3, parallelism: 4 });

    const tuned = assembleAuthFromEnv({
      ...validEnv(),
      AUTH_ARGON2_MEMORY_COST: '131072',
      AUTH_ARGON2_TIME_COST: '4',
      AUTH_ARGON2_PARALLELISM: '2',
    });
    expect(tuned.argon2).toEqual({ memoryCost: 131072, timeCost: 4, parallelism: 2 });
  });

  test('clés absentes, illisibles ou kid actif inconnu → violations listées', () => {
    expect(() => assembleAuthFromEnv({})).toThrow(/AUTH_SIGNING_KEYS manquant/);
    expect(() =>
      assembleAuthFromEnv({ AUTH_SIGNING_KEYS: '{"K1":"pasdubase64der"}', AUTH_ACTIVE_KEY_ID: 'K1' }),
    ).toThrow(/AUTH_SIGNING_KEYS invalide/);
    expect(() =>
      assembleAuthFromEnv({ ...validEnv(), AUTH_ACTIVE_KEY_ID: 'ABSENT' }),
    ).toThrow(/absent de AUTH_SIGNING_KEYS/);
  });

  test('une clé qui n\'est pas Ed25519 → refusée (EdDSA exigé, tranché Q2)', () => {
    const { generateKeyPairSync } = jest.requireActual<typeof import('crypto')>('crypto');
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 })
      .privateKey.export({ format: 'der', type: 'pkcs8' })
      .toString('base64');
    expect(() =>
      assembleAuthFromEnv({ AUTH_SIGNING_KEYS: JSON.stringify({ R1: rsa }), AUTH_ACTIVE_KEY_ID: 'R1' }),
    ).toThrow(/Ed25519 exigé/);
  });
});
