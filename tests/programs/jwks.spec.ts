import {
  createPublicKey,
  generateKeyPairSync,
  sign as ed25519Sign,
  verify as ed25519Verify,
} from 'crypto';
import { buildJwks } from '../../src/programs/jwks';
import { testAuthAssembly } from '../helpers/auth';

// Le JWKS : des clés PUBLIQUES, une forme CLOSE, et rien d'autre. La fuite
// qui tuerait tout — une composante privée publiée — est prouvée absente par
// Object.keys, pas par relecture humaine.
describe('buildJwks', () => {
  test('forme close : exactement kty/crv/kid/x/use/alg — et JAMAIS de composante privée', () => {
    const config = testAuthAssembly();
    const jwks = buildJwks(config);

    expect(Object.keys(jwks)).toEqual(['keys']);
    expect(jwks.keys).toHaveLength(1);
    for (const key of jwks.keys) {
      expect(Object.keys(key).sort()).toEqual(['alg', 'crv', 'kid', 'kty', 'use', 'x']);
      expect(key).toMatchObject({ kty: 'OKP', crv: 'Ed25519', use: 'sig', alg: 'EdDSA' });
    }
    // Ceinture : la sérialisation complète ne porte aucun champ « d ».
    expect(JSON.stringify(jwks)).not.toMatch(/"d"\s*:/);
  });

  test('toutes les clés du trousseau sont publiées, chacune sous son kid', () => {
    const base = testAuthAssembly();
    const second = generateKeyPairSync('ed25519');
    base.keys.set('T2', {
      kid: 'T2',
      privateKey: second.privateKey,
      publicKey: createPublicKey(second.privateKey),
    });

    const jwks = buildJwks(base);
    expect(jwks.keys.map((k) => k.kid).sort()).toEqual(['T1', 'T2']);
  });

  test('un vérificateur externe reconstruit la clé depuis le JWK et vérifie une vraie signature', () => {
    const config = testAuthAssembly();
    const jwk = buildJwks(config).keys[0]!;

    // Ce que fera Scolaria : reconstruire la clé publique depuis le JWKS.
    const rebuilt = createPublicKey({
      key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
      format: 'jwk',
    });

    const message = Buffer.from('en-tete.charge-utile', 'utf8');
    const signature = ed25519Sign(null, message, config.keys.get('T1')!.privateKey);
    expect(ed25519Verify(null, message, rebuilt, signature)).toBe(true);
    // Et une signature d'une AUTRE clé ne vérifie pas.
    const intruder = generateKeyPairSync('ed25519').privateKey;
    expect(ed25519Verify(null, message, rebuilt, ed25519Sign(null, message, intruder))).toBe(false);
  });
});
