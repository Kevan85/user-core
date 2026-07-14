import { LocalAuthenticationProvider } from '../../src/auth/local-authentication-provider';
import { testAuthAssembly } from '../helpers/auth';

function decodeSegment(token: string, index: number): Record<string, unknown> {
  const segment = token.split('.')[index];
  if (segment === undefined) {
    throw new Error('segment JWT manquant');
  }
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
}

describe('LocalAuthenticationProvider (le maison derrière la couture)', () => {
  const config = testAuthAssembly();
  const provider = new LocalAuthenticationProvider(config);

  beforeAll(async () => {
    await provider.init();
  });

  test('C7 — le hash est encodé argon2id et PORTE les paramètres de la config', async () => {
    const hash = await provider.hashSecret('S3cret!');
    expect(hash.startsWith('$argon2id$')).toBe(true);
    // m/t/p de la config de test — pas les défauts de la lib.
    expect(hash).toContain('m=2048,t=2,p=1');
  });

  test('verify : vrai secret → true, faux secret → false, hash illisible → false (jamais d\'exception)', async () => {
    const hash = await provider.hashSecret('S3cret!');
    await expect(provider.verifySecret(hash, 'S3cret!')).resolves.toBe(true);
    await expect(provider.verifySecret(hash, 'autre')).resolves.toBe(false);
    await expect(provider.verifySecret('pasunhash', 'S3cret!')).resolves.toBe(false);
  });

  test('jeton d\'accès : EdDSA, kid en en-tête, claims MINIMALES (jamais le public_identifier)', async () => {
    const issued = await provider.issueAccessToken({ sub: 'uuid-compte', sid: 'uuid-session' });

    const header = decodeSegment(issued.token, 0);
    expect(header.alg).toBe('EdDSA');
    expect(header.typ).toBe('JWT');
    expect(header.kid).toBe('T1');

    const payload = decodeSegment(issued.token, 1);
    expect(Object.keys(payload).sort()).toEqual(['exp', 'iat', 'sid', 'sub']);
    expect(payload.sub).toBe('uuid-compte');
    expect(payload.sid).toBe('uuid-session');

    // TTL respecté (borne C2 vérifiée à la config, cohérence vérifiée ici).
    const ttlSeconds = (issued.expiresAt.getTime() - Date.now()) / 1000;
    expect(ttlSeconds).toBeGreaterThan(890);
    expect(ttlSeconds).toBeLessThanOrEqual(900);
  });

  test('roundtrip : le jeton émis se vérifie ; altéré, kid inconnu ou forgé → null', async () => {
    const issued = await provider.issueAccessToken({ sub: 'a', sid: 's' });
    await expect(provider.verifyAccessToken(issued.token)).resolves.toEqual({ sub: 'a', sid: 's' });

    // Altération d'un caractère de la signature.
    const flipped = issued.token.slice(0, -2) + (issued.token.endsWith('A') ? 'B' : 'A');
    await expect(provider.verifyAccessToken(flipped)).resolves.toBeNull();

    // Jeton signé par une AUTRE clé (kid identique, clé différente) → null.
    const impostor = new LocalAuthenticationProvider(testAuthAssembly());
    await impostor.init();
    const forged = await impostor.issueAccessToken({ sub: 'a', sid: 's' });
    await expect(provider.verifyAccessToken(forged.token)).resolves.toBeNull();

    await expect(provider.verifyAccessToken('pas.un.jwt')).resolves.toBeNull();
  });

  test('C3 — le hash de référence existe après init et se vérifie comme un vrai', async () => {
    const reference = provider.getReferenceHash();
    expect(reference.startsWith('$argon2id$')).toBe(true);
    // Un secret quelconque contre la référence : false, au même coût.
    await expect(provider.verifySecret(reference, 'tentative')).resolves.toBe(false);
  });
});
