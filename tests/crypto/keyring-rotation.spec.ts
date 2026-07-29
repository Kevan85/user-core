import { randomBytes } from 'crypto';
import { decrypt, encrypt, keyIdOf } from '../../src/crypto/aes-gcm';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import {
  assembleProofCodeKeyring,
  codeHashEquals,
  hashProofCode,
  hashProofCodeUnder,
} from '../../src/proving/proof-code';
import { fullKeyringEnv } from '../helpers/keyring-env';

/**
 * ROTATION des trousseaux ordinaires (LOT prod, étapes 4a/4b) : une VRAIE
 * rotation — deux assemblages successifs sur les MÊMES matériaux, comme deux
 * déploiements — pas deux clés posées d'avance dans un seul env.
 */
const E1 = randomBytes(32).toString('base64');
const E2 = randomBytes(32).toString('base64');
const C1 = randomBytes(32).toString('base64');
const C2 = randomBytes(32).toString('base64');

describe('4a — rotation du trousseau de CHIFFREMENT (le geste ordinaire)', () => {
  test('écrit sous E1 hier, tourné vers E2 aujourd\'hui : l\'ancien se relit, le neuf part sous E2', () => {
    const before = assembleCryptoFromEnv(
      fullKeyringEnv({
        USER_CORE_ENC_KEYS: JSON.stringify({ E1 }),
        USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
      }),
    );
    const legacyToken = encrypt(before.encryption, '+8801700000123');

    // Le déploiement de rotation : E2 devient active, E1 reste lisible.
    const after = assembleCryptoFromEnv(
      fullKeyringEnv({
        USER_CORE_ENC_KEYS: JSON.stringify({ E1, E2 }),
        USER_CORE_ENC_ACTIVE_KEY_ID: 'E2',
      }),
    );
    expect(decrypt(after.encryption, legacyToken)).toBe('+8801700000123');
    expect(keyIdOf(legacyToken)).toBe('E1');
    expect(keyIdOf(encrypt(after.encryption, '+8801700000456'))).toBe('E2');
  });

  test('le RETRAIT de l\'ancienne clé est le vrai point de non-retour — et il est explicite', () => {
    const before = assembleCryptoFromEnv(
      fullKeyringEnv({
        USER_CORE_ENC_KEYS: JSON.stringify({ E1 }),
        USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
      }),
    );
    const legacyToken = encrypt(before.encryption, '+8801700000123');
    const withdrawn = assembleCryptoFromEnv(
      fullKeyringEnv({
        USER_CORE_ENC_KEYS: JSON.stringify({ E2 }),
        USER_CORE_ENC_ACTIVE_KEY_ID: 'E2',
      }),
    );
    // Refus EXPLICITE (l'exploitation doit voir qu'une clé manque), jamais
    // un déchiffrement silencieusement faux.
    expect(() => decrypt(withdrawn.encryption, legacyToken)).toThrow(/absente du trousseau/);
  });
});

describe('4b — rotation du trousseau des CODES de possession (fenêtre de recouvrement)', () => {
  test('un code émis sous C1 se vérifie encore pendant sa fenêtre après la bascule vers C2', () => {
    const before = assembleProofCodeKeyring(
      fullKeyringEnv({
        USER_CORE_PROOF_CODE_KEYS: JSON.stringify({ C1 }),
        USER_CORE_PROOF_CODE_ACTIVE_KEY_ID: 'C1',
      }),
    );
    // La ligne écrite hier : le registre porte (proof_code_key_id, hmac).
    const stored = hashProofCode(before, '123456');
    expect(stored.keyId).toBe('C1');

    const after = assembleProofCodeKeyring(
      fullKeyringEnv({
        USER_CORE_PROOF_CODE_KEYS: JSON.stringify({ C1, C2 }),
        USER_CORE_PROOF_CODE_ACTIVE_KEY_ID: 'C2',
      }),
    );
    // La vérification recalcule sous la clé NOMMÉE par la ligne — le code en
    // vol traverse la rotation (TTL 300 s, la fenêtre suffit).
    const replayed = hashProofCodeUnder(after, stored.keyId, '123456');
    expect(replayed).not.toBeNull();
    expect(codeHashEquals(replayed as string, stored.hmac)).toBe(true);
    // Et les codes neufs partent sous C2.
    expect(hashProofCode(after, '654321').keyId).toBe('C2');
  });

  test('C1 retirée du trousseau : le code en vol est REFUSÉ proprement (null), jamais une fausse égalité', () => {
    const before = assembleProofCodeKeyring(
      fullKeyringEnv({
        USER_CORE_PROOF_CODE_KEYS: JSON.stringify({ C1 }),
        USER_CORE_PROOF_CODE_ACTIVE_KEY_ID: 'C1',
      }),
    );
    const stored = hashProofCode(before, '123456');
    const withdrawn = assembleProofCodeKeyring(
      fullKeyringEnv({
        USER_CORE_PROOF_CODE_KEYS: JSON.stringify({ C2 }),
        USER_CORE_PROOF_CODE_ACTIVE_KEY_ID: 'C2',
      }),
    );
    expect(hashProofCodeUnder(withdrawn, stored.keyId, '123456')).toBeNull();
  });
});
