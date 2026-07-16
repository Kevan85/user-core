import { randomBytes } from 'crypto';
import { keyIdOf } from '../../src/crypto/aes-gcm';
import { assembleCryptoFromEnv } from '../../src/crypto/keyring';
import {
  CivilIdentityError,
  decryptCivilIdentity,
  encryptCivilIdentity,
  ERASURE_SALT_BYTES,
  generateErasureSalt,
  PersonCivilIdentity,
} from '../../src/crypto/person-identity';

// Le module d'identité civile : dérivation par personne (HKDF + sel), blob
// AES-256-GCM, birth_year calculé par le SEUL écrivain. Tests unitaires —
// la base n'intervient pas ici (le schéma 014 a sa propre suite).

const E1 = randomBytes(32).toString('base64');
const E2 = randomBytes(32).toString('base64');
const H1 = randomBytes(32).toString('base64');

function assembly(keys: Record<string, string>, active: string) {
  return assembleCryptoFromEnv({
    USER_CORE_ENC_KEYS: JSON.stringify(keys),
    USER_CORE_ENC_ACTIVE_KEY_ID: active,
    USER_CORE_HMAC_KEYS: JSON.stringify({ H1 }),
    USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
  });
}

const IDENTITY: PersonCivilIdentity = {
  nameComponents: ['Kabeya', 'Mwamba', 'Junior'],
  displayName: 'Kabeya Mwamba',
  birthDate: '2010-03-12',
};

describe('person-identity — dérivation par personne et blob chiffré', () => {
  const crypto = assembly({ E1 }, 'E1');

  test('aller-retour : le blob se déchiffre à l’identique, birth_year vient de la même date', () => {
    const salt = generateErasureSalt();
    const enc = encryptCivilIdentity(crypto.encryption, salt, IDENTITY);

    expect(enc.encKeyId).toBe('E1');
    expect(enc.birthYear).toBe(2010);
    // Le jeton porte l’identifiant de clé du TROUSSEAU (pas la dérivée) :
    // c’est lui que 014 stocke dans enc_key_id.
    expect(keyIdOf(enc.token)).toBe('E1');

    expect(decryptCivilIdentity(crypto.encryption, salt, enc.token, enc.birthYear)).toEqual(
      IDENTITY,
    );
  });

  test('re-dérivation à la lecture (parade P4) : une divergence blob/borne d’âge refuse de servir', () => {
    const salt = generateErasureSalt();
    // Le blob dit 2004 ; la colonne (simulée par une écriture partielle qui a
    // laissé l’ancienne valeur) dit 2010 : la lecture doit refuser, et
    // l’erreur ne doit porter AUCUNE des deux valeurs.
    const enc = encryptCivilIdentity(crypto.encryption, salt, {
      ...IDENTITY,
      birthDate: '2004-03-12',
    });
    try {
      decryptCivilIdentity(crypto.encryption, salt, enc.token, 2010);
      throw new Error('une CivilIdentityError était attendue');
    } catch (err) {
      expect(err).toBeInstanceOf(CivilIdentityError);
      expect((err as Error).message).toMatch(/divergence/);
      expect((err as Error).message).not.toContain('2004');
      expect((err as Error).message).not.toContain('2010');
    }
  });

  test('le clair ne figure nulle part dans le jeton', () => {
    const salt = generateErasureSalt();
    const enc = encryptCivilIdentity(crypto.encryption, salt, IDENTITY);
    expect(enc.token).not.toContain('Kabeya');
    expect(enc.token).not.toContain('2010');
  });

  test('crypto-destruction : sans LE sel, le blob est illisible à jamais', () => {
    const salt = generateErasureSalt();
    const enc = encryptCivilIdentity(crypto.encryption, salt, IDENTITY);

    // Un autre sel (= le sel détruit puis « deviné ») : échec du tag GCM.
    expect(() =>
      decryptCivilIdentity(crypto.encryption, generateErasureSalt(), enc.token, enc.birthYear),
    ).toThrow(/déchiffrement impossible/);
  });

  test('deux personnes, même identité : sels distincts, jetons sans rapport', () => {
    const encA = encryptCivilIdentity(crypto.encryption, generateErasureSalt(), IDENTITY);
    const encB = encryptCivilIdentity(crypto.encryption, generateErasureSalt(), IDENTITY);
    expect(encA.token).not.toBe(encB.token);
  });

  test('rotation du trousseau : un blob écrit sous E1 reste lisible quand E2 devient active', () => {
    const salt = generateErasureSalt();
    const enc = encryptCivilIdentity(crypto.encryption, salt, IDENTITY);

    const rotated = assembly({ E1, E2 }, 'E2');
    expect(decryptCivilIdentity(rotated.encryption, salt, enc.token, enc.birthYear)).toEqual(
      IDENTITY,
    );
    // Et un nouveau blob part sous la nouvelle clé active.
    expect(encryptCivilIdentity(rotated.encryption, salt, IDENTITY).encKeyId).toBe('E2');
  });

  test('sel de mauvaise taille : refus net, au chiffrement comme au déchiffrement', () => {
    const short = randomBytes(ERASURE_SALT_BYTES - 1);
    expect(() => encryptCivilIdentity(crypto.encryption, short, IDENTITY)).toThrow(
      CivilIdentityError,
    );
    expect(() => decryptCivilIdentity(crypto.encryption, short, 'v1.E1.x.y.z', 2010)).toThrow(
      CivilIdentityError,
    );
  });

  describe('façade de validation — erreurs propres, jamais une valeur dedans', () => {
    const salt = generateErasureSalt();

    function rejects(identity: PersonCivilIdentity, reason: RegExp): void {
      expect(() => encryptCivilIdentity(crypto.encryption, salt, identity)).toThrow(reason);
    }

    test('composantes de nom : jamais zéro, jamais neuf, jamais vide', () => {
      rejects({ ...IDENTITY, nameComponents: [] }, /composantes de nom/);
      rejects(
        { ...IDENTITY, nameComponents: Array.from({ length: 9 }, () => 'X') },
        /composantes de nom/,
      );
      rejects({ ...IDENTITY, nameComponents: ['Kabeya', '   '] }, /composante de nom/);
    });

    test('nom d’affichage borné (même borne que le profil de compte)', () => {
      rejects({ ...IDENTITY, displayName: '' }, /nom d'affichage/);
      rejects({ ...IDENTITY, displayName: 'X'.repeat(81) }, /nom d'affichage/);
    });

    test('date de naissance : forme, calendrier, futur, borne basse', () => {
      rejects({ ...IDENTITY, birthDate: '12/03/2010' }, /AAAA-MM-JJ/);
      rejects({ ...IDENTITY, birthDate: '2010-02-30' }, /inexistante au calendrier/);
      rejects({ ...IDENTITY, birthDate: '2999-01-01' }, /dans le futur/);
      rejects({ ...IDENTITY, birthDate: '1899-12-31' }, /antérieure à 1900/);
    });

    test('le message d’erreur ne porte JAMAIS la valeur refusée', () => {
      try {
        encryptCivilIdentity(crypto.encryption, salt, { ...IDENTITY, birthDate: '2999-01-01' });
        throw new Error('une CivilIdentityError était attendue');
      } catch (err) {
        expect(err).toBeInstanceOf(CivilIdentityError);
        expect((err as Error).message).not.toContain('2999');
        expect((err as Error).message).not.toContain('Kabeya');
      }
    });
  });
});
