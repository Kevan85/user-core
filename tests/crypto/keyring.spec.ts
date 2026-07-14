import { randomBytes } from 'crypto';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import { ConfigViolations } from '../../src/bootstrap/assembly';

function key(bytes = 32): string {
  return randomBytes(bytes).toString('base64');
}

function validEnv(): NodeJS.ProcessEnv {
  return {
    USER_CORE_ENC_KEYS: JSON.stringify({ E1: key(), E2: key() }),
    USER_CORE_ENC_ACTIVE_KEY_ID: 'E2',
    USER_CORE_HMAC_KEYS: JSON.stringify({ H1: key() }),
    USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
  };
}

describe('assembleCryptoFromEnv — deux trousseaux, deux cycles de vie', () => {
  test('assemblage nominal : clé active + anciennes clés lisibles', () => {
    const crypto = assembleCryptoFromEnv(validEnv());
    expect(crypto.encryption.activeKeyId).toBe('E2');
    expect(crypto.encryption.get('E1')).toBeDefined(); // ancienne : lecture OK
    expect(crypto.encryption.active().keyId).toBe('E2');
    expect(crypto.fingerprint.activeKeyId).toBe('H1');
  });

  test('clé AES de mauvaise taille → refus de boot (AES-256 = 32 octets exacts)', () => {
    const env = { ...validEnv(), USER_CORE_ENC_KEYS: JSON.stringify({ E1: key(16) }) };
    expect(() => assembleCryptoFromEnv(env)).toThrow(ConfigViolations);
    expect(() => assembleCryptoFromEnv(env)).toThrow(/32 octets exigés, 16 reçus/);
  });

  test('clé d\'empreinte trop courte → refus de boot', () => {
    const env = { ...validEnv(), USER_CORE_HMAC_KEYS: JSON.stringify({ H1: key(16) }) };
    expect(() => assembleCryptoFromEnv(env)).toThrow(/32 octets minimum/);
  });

  test('clé active absente du trousseau → refus de boot', () => {
    const env = { ...validEnv(), USER_CORE_ENC_ACTIVE_KEY_ID: 'FANTOME' };
    expect(() => assembleCryptoFromEnv(env)).toThrow(/absent de USER_CORE_ENC_KEYS/);
  });

  test('trousseaux manquants → toutes les violations listées d\'un bloc', () => {
    try {
      assembleCryptoFromEnv({});
      throw new Error('un refus était attendu');
    } catch (err) {
      const message = (err as Error).message;
      expect(message).toMatch(/USER_CORE_ENC_KEYS manquant/);
      expect(message).toMatch(/USER_CORE_HMAC_KEYS manquant/);
    }
  });

  test('la MÊME valeur dans les deux trousseaux → refus (cycles de vie distincts)', () => {
    const shared = key();
    const env = {
      USER_CORE_ENC_KEYS: JSON.stringify({ E1: shared }),
      USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
      USER_CORE_HMAC_KEYS: JSON.stringify({ H1: shared }),
      USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
    };
    expect(() => assembleCryptoFromEnv(env)).toThrow(/MÊME valeur/);
  });

  test('un secret de clé ne fuit JAMAIS dans un message de violation', () => {
    const secret = key();
    const env = {
      USER_CORE_ENC_KEYS: JSON.stringify({ E1: secret }),
      USER_CORE_ENC_ACTIVE_KEY_ID: 'ABSENT',
      USER_CORE_HMAC_KEYS: JSON.stringify({ H1: key() }),
      USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
    };
    try {
      assembleCryptoFromEnv(env);
      throw new Error('un refus était attendu');
    } catch (err) {
      expect((err as Error).message).not.toContain(secret);
      expect((err as Error).message).toContain('ABSENT'); // l'identifiant, oui
    }
  });
});
