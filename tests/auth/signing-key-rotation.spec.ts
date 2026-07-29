import { createPublicKey, generateKeyPairSync } from 'crypto';
import type { SigningKeyPair } from '../../src/auth/auth-config';
import { LocalAuthenticationProvider } from '../../src/auth/local-authentication-provider';
import { buildJwks } from '../../src/programs/jwks';
import { testAuthAssembly } from '../helpers/auth';

/**
 * ROTATION des clés de signature Ed25519 (LOT prod, étape 4c) : le kid vit
 * dans l'en-tête depuis le premier jeton — la rotation n'est jamais une
 * crise. On prouve le RECOUVREMENT : pendant le TTL (900 s), les jetons
 * signés sous l'ancienne clé restent vérifiables, et le JWKS sert les deux.
 */
function keyPair(kid: string): SigningKeyPair {
  const { privateKey } = generateKeyPairSync('ed25519');
  return { kid, privateKey, publicKey: createPublicKey(privateKey) };
}

describe('4c — rotation des clés de signature des jetons', () => {
  test('recouvrement : un jeton signé sous K1 se vérifie après la bascule vers K2 ; les neufs partent sous K2', async () => {
    const k1 = keyPair('K1');
    const k2 = keyPair('K2');

    const before = new LocalAuthenticationProvider(
      testAuthAssembly({ activeKid: 'K1', keys: new Map([['K1', k1]]) }),
    );
    await before.init();
    const legacy = await before.issueAccessToken({ sub: 'compte', sid: 'session' });

    // Le déploiement de rotation : K2 signe, K1 reste au trousseau (lecture).
    const after = new LocalAuthenticationProvider(
      testAuthAssembly({
        activeKid: 'K2',
        keys: new Map([
          ['K1', k1],
          ['K2', k2],
        ]),
      }),
    );
    await after.init();

    await expect(after.verifyAccessToken(legacy.token)).resolves.toEqual({
      sub: 'compte',
      sid: 'session',
    });
    const fresh = await after.issueAccessToken({ sub: 'compte', sid: 'session' });
    const header = JSON.parse(
      Buffer.from(fresh.token.split('.')[0] ?? '', 'base64url').toString('utf8'),
    ) as { kid?: string };
    expect(header.kid).toBe('K2');
  });

  test('le JWKS du recouvrement publie LES DEUX kids — un programme vérifie l\'ancien comme le neuf', () => {
    const jwks = buildJwks(
      testAuthAssembly({
        activeKid: 'K2',
        keys: new Map([
          ['K1', keyPair('K1')],
          ['K2', keyPair('K2')],
        ]),
      }),
    );
    expect(jwks.keys.map((k) => k.kid).sort()).toEqual(['K1', 'K2']);
  });

  test('après RETRAIT de K1 (fin de recouvrement) : les jetons K1 meurent proprement (null)', async () => {
    const k1 = keyPair('K1');
    const before = new LocalAuthenticationProvider(
      testAuthAssembly({ activeKid: 'K1', keys: new Map([['K1', k1]]) }),
    );
    await before.init();
    const legacy = await before.issueAccessToken({ sub: 'compte', sid: 'session' });

    const withdrawn = new LocalAuthenticationProvider(
      testAuthAssembly({ activeKid: 'K2', keys: new Map([['K2', keyPair('K2')]]) }),
    );
    await withdrawn.init();
    await expect(withdrawn.verifyAccessToken(legacy.token)).resolves.toBeNull();
  });
});
