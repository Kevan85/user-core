import { randomBytes } from 'crypto';
import { assembleKeyringsFromEnv } from '../../src/crypto/keyring';
import { ConfigViolations } from '../../src/bootstrap/assembly';

/**
 * Dette ② (LOT prod, étape 1) : l'assemblage de BOOT parse les QUATRE
 * trousseaux d'un bloc et refuse toute paire de clés partageant une VALEUR —
 * entre trousseaux comme au sein d'un même trousseau. Quatre usages, quatre
 * cycles de vie : un secret ne sert jamais deux fois.
 */

function key(bytes = 32): string {
  return randomBytes(bytes).toString('base64');
}

const FAMILIES = [
  ['USER_CORE_ENC_KEYS', 'USER_CORE_ENC_ACTIVE_KEY_ID', 'E1'],
  ['USER_CORE_HMAC_KEYS', 'USER_CORE_HMAC_ACTIVE_KEY_ID', 'H1'],
  ['USER_CORE_PROOF_CODE_KEYS', 'USER_CORE_PROOF_CODE_ACTIVE_KEY_ID', 'C1'],
  ['USER_CORE_REF_HMAC_KEYS', 'USER_CORE_REF_HMAC_ACTIVE_KEY_ID', 'R1'],
] as const;

function validEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [keysVar, activeVar, keyId] of FAMILIES) {
    env[keysVar] = JSON.stringify({ [keyId]: key() });
    env[activeVar] = keyId;
  }
  return env;
}

describe('assembleKeyringsFromEnv — quatre trousseaux, un seul assemblage de boot', () => {
  test('assemblage nominal : les quatre trousseaux sortent, chacun sa clé active', () => {
    const keyrings = assembleKeyringsFromEnv(validEnv());
    expect(keyrings.encryption.activeKeyId).toBe('E1');
    expect(keyrings.fingerprint.activeKeyId).toBe('H1');
    expect(keyrings.proofCode.activeKeyId).toBe('C1');
    expect(keyrings.reference.activeKeyId).toBe('R1');
    expect(keyrings.proofCode.keys.get('C1')).toBeDefined();
    expect(keyrings.reference.keys.get('R1')).toBeDefined();
  });

  // Les SIX paires de trousseaux, énumérées : chaque collision inter-trousseau
  // refuse le boot. Une boucle, pas un échantillon — le jour où une paire
  // échappe au contrôle, ce test la nomme.
  const pairs: [string, string, string, string][] = [];
  FAMILIES.forEach((first, index) => {
    for (const second of FAMILIES.slice(index + 1)) {
      pairs.push([first[0], first[2], second[0], second[2]]);
    }
  });
  test.each(pairs)(
    'collision de valeur entre %s (clé %s) et %s (clé %s) → refus de boot',
    (firstVar, firstId, secondVar, secondId) => {
      const shared = key();
      const env = validEnv();
      env[firstVar] = JSON.stringify({ [firstId]: shared });
      env[secondVar] = JSON.stringify({ [secondId]: shared });
      expect(() => assembleKeyringsFromEnv(env)).toThrow(ConfigViolations);
      expect(() => assembleKeyringsFromEnv(env)).toThrow(/MÊME valeur/);
    },
  );

  test('deux clés identiques DANS un même trousseau → refus (une rotation qui ne tourne rien)', () => {
    const duplicated = key();
    const env = validEnv();
    env.USER_CORE_ENC_KEYS = JSON.stringify({ E1: duplicated, E2: duplicated });
    env.USER_CORE_ENC_ACTIVE_KEY_ID = 'E2';
    expect(() => assembleKeyringsFromEnv(env)).toThrow(ConfigViolations);
    expect(() => assembleKeyringsFromEnv(env)).toThrow(/ne tourne rien/);
  });

  test('une ANCIENNE clé en collision refuse aussi : le contrôle couvre tout le trousseau, pas la seule clé active', () => {
    const shared = key();
    const env = validEnv();
    // E1 est active, E0 est une ancienne clé — c'est E0 qui partage sa valeur
    // avec le trousseau des codes : le boot refuse quand même.
    env.USER_CORE_ENC_KEYS = JSON.stringify({ E0: shared, E1: key() });
    env.USER_CORE_PROOF_CODE_KEYS = JSON.stringify({ C1: shared });
    expect(() => assembleKeyringsFromEnv(env)).toThrow(/MÊME valeur/);
  });

  test('config vide : les violations des QUATRE trousseaux listées d\'un seul bloc', () => {
    try {
      assembleKeyringsFromEnv({});
      throw new Error('un refus était attendu');
    } catch (err) {
      const message = (err as Error).message;
      for (const [keysVar] of FAMILIES) {
        expect(message).toMatch(new RegExp(`${keysVar} manquant`));
      }
    }
  });

  test('un secret de clé ne fuit JAMAIS dans un message de collision — les identifiants, oui', () => {
    const shared = key();
    const env = validEnv();
    env.USER_CORE_PROOF_CODE_KEYS = JSON.stringify({ C1: shared });
    env.USER_CORE_REF_HMAC_KEYS = JSON.stringify({ R1: shared });
    try {
      assembleKeyringsFromEnv(env);
      throw new Error('un refus était attendu');
    } catch (err) {
      const message = (err as Error).message;
      expect(message).not.toContain(shared);
      expect(message).toContain('C1');
      expect(message).toContain('R1');
    }
  });
});
