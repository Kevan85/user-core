import { randomBytes } from 'crypto';
import { decrypt, DecryptionError, encrypt, keyIdOf } from '../../src/crypto/aes-gcm';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';

const PHONE = '+243812345678';

function keyring(keys: Record<string, string>, active: string) {
  return assembleCryptoFromEnv({
    USER_CORE_ENC_KEYS: JSON.stringify(keys),
    USER_CORE_ENC_ACTIVE_KEY_ID: active,
    USER_CORE_HMAC_KEYS: JSON.stringify({ H1: randomBytes(32).toString('base64') }),
    USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
  }).encryption;
}

const E1 = randomBytes(32).toString('base64');
const E2 = randomBytes(32).toString('base64');

describe('AES-256-GCM (chiffrement au repos de la PII)', () => {
  test('roundtrip : ce qui est chiffré se déchiffre, et le clair n\'apparaît pas dans le jeton', () => {
    const ring = keyring({ E1 }, 'E1');
    const token = encrypt(ring, PHONE);
    expect(token).not.toContain(PHONE);
    expect(token).not.toContain('812345678');
    expect(decrypt(ring, token)).toBe(PHONE);
  });

  test('deux chiffrements du MÊME numéro donnent deux jetons différents (IV aléatoire)', () => {
    const ring = keyring({ E1 }, 'E1');
    expect(encrypt(ring, PHONE)).not.toBe(encrypt(ring, PHONE));
  });

  test('ROTATION : une valeur écrite sous l\'ancienne clé reste déchiffrable', () => {
    const before = keyring({ E1 }, 'E1');
    const legacyToken = encrypt(before, PHONE);
    expect(keyIdOf(legacyToken)).toBe('E1');

    // On tourne : E2 devient active, E1 reste au trousseau (lecture).
    const after = keyring({ E1, E2 }, 'E2');
    expect(decrypt(after, legacyToken)).toBe(PHONE); // l'ancien se lit encore
    const freshToken = encrypt(after, PHONE);
    expect(keyIdOf(freshToken)).toBe('E2'); // le neuf est sous la nouvelle clé
    expect(decrypt(after, freshToken)).toBe(PHONE);
  });

  test('clé retirée du trousseau → refus explicite (l\'exploitation doit le voir)', () => {
    const before = keyring({ E1 }, 'E1');
    const token = encrypt(before, PHONE);
    const withoutE1 = keyring({ E2 }, 'E2');
    expect(() => decrypt(withoutE1, token)).toThrow(DecryptionError);
    expect(() => decrypt(withoutE1, token)).toThrow(/clé « E1 » absente/);
  });

  test('altération du chiffré ou du tag → refus (authentification GCM)', () => {
    const ring = keyring({ E1 }, 'E1');
    const token = encrypt(ring, PHONE);
    const parts = token.split('.');

    const flippedCipher = [...parts];
    flippedCipher[4] = Buffer.from('autre valeur totale').toString('base64url');
    expect(() => decrypt(ring, flippedCipher.join('.'))).toThrow(/authentification/);

    const flippedTag = [...parts];
    flippedTag[3] = randomBytes(16).toString('base64url');
    expect(() => decrypt(ring, flippedTag.join('.'))).toThrow(/authentification/);
  });

  test('substitution du key_id (AAD) → refus : un jeton ne change pas de clé', () => {
    const ring = keyring({ E1, E2 }, 'E1');
    const token = encrypt(ring, PHONE);
    const parts = token.split('.');
    parts[1] = 'E2'; // on prétend que le jeton a été chiffré sous E2
    expect(() => decrypt(ring, parts.join('.'))).toThrow(/authentification/);
  });

  test('jeton malformé → refus, et le message ne contient NI clair NI clé', () => {
    const ring = keyring({ E1 }, 'E1');
    try {
      decrypt(ring, 'nimportequoi');
      throw new Error('un refus était attendu');
    } catch (err) {
      const message = (err as Error).message;
      expect(message).toMatch(/forme du jeton inattendue/);
      expect(message).not.toContain(E1);
      expect(message).not.toContain(PHONE);
    }
  });
});
