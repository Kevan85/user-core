import { createHash, randomBytes } from 'crypto';
import {
  fingerprintEquals,
  fingerprintOf,
  fingerprintUnder,
} from '../../src/crypto/fingerprint';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';

const PHONE = '+243812345678';
const H1 = randomBytes(32).toString('base64');
const H2 = randomBytes(32).toString('base64');

function keyring(keys: Record<string, string>, active: string) {
  return assembleCryptoFromEnv({
    USER_CORE_ENC_KEYS: JSON.stringify({ E1: randomBytes(32).toString('base64') }),
    USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
    USER_CORE_HMAC_KEYS: JSON.stringify(keys),
    USER_CORE_HMAC_ACTIVE_KEY_ID: active,
  }).fingerprint;
}

describe('Empreinte HMAC déterministe (recherche d\'unicité, jamais le clair)', () => {
  test('déterministe sous une clé donnée : même numéro → même empreinte', () => {
    const ring = keyring({ H1 }, 'H1');
    const a = fingerprintOf(ring, PHONE);
    const b = fingerprintOf(ring, PHONE);
    expect(a.value).toBe(b.value);
    expect(a.hmacKeyId).toBe('H1');
    // Le clair ne transparaît nulle part.
    expect(a.value).not.toContain('812345678');
  });

  test('DEUX CLÉS → DEUX EMPREINTES du même numéro : d\'où l\'unicité sur le COUPLE', () => {
    const under1 = fingerprintOf(keyring({ H1 }, 'H1'), PHONE);
    const under2 = fingerprintOf(keyring({ H2 }, 'H2'), PHONE);
    expect(under1.value).not.toBe(under2.value);
    // C'est exactement le piège que l'index (hmac_key_id, empreinte) ferme :
    // une unicité posée sur l'empreinte SEULE laisserait cohabiter ces deux
    // lignes — la même SIM, deux revendications actives, en silence.
    expect(under1.hmacKeyId).not.toBe(under2.hmacKeyId);
  });

  test('l\'empreinte n\'est PAS un SHA-256 nu (un condensat non salé est réversible)', () => {
    const ring = keyring({ H1 }, 'H1');
    const naive = createHash('sha256').update(PHONE, 'utf8').digest('hex');
    expect(fingerprintOf(ring, PHONE).value).not.toBe(naive);
  });

  test('fingerprintUnder : recalcul sous une clé ANCIENNE nommée (vérification d\'une ligne existante)', () => {
    const ring = keyring({ H1, H2 }, 'H2'); // H2 active, H1 encore lisible
    const legacy = fingerprintUnder(ring, 'H1', PHONE);
    expect(legacy?.hmacKeyId).toBe('H1');
    // Et il correspond bien à ce qu'aurait produit H1 quand elle était active.
    expect(legacy?.value).toBe(fingerprintOf(keyring({ H1 }, 'H1'), PHONE).value);
    // L'empreinte active, elle, est celle de H2.
    expect(fingerprintOf(ring, PHONE).hmacKeyId).toBe('H2');
  });

  test('fingerprintUnder avec une clé inconnue → null (jamais une empreinte fausse)', () => {
    expect(fingerprintUnder(keyring({ H1 }, 'H1'), 'ABSENTE', PHONE)).toBeNull();
  });

  test('comparaison à temps constant : égalité vraie, inégalité, tailles différentes', () => {
    const ring = keyring({ H1 }, 'H1');
    const a = fingerprintOf(ring, PHONE).value;
    const b = fingerprintOf(ring, '+243990000000').value;
    expect(fingerprintEquals(a, a)).toBe(true);
    expect(fingerprintEquals(a, b)).toBe(false);
    expect(fingerprintEquals(a, 'court')).toBe(false);
  });
});
