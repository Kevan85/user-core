import { encrypt } from '../crypto/aes-gcm';
import { fingerprintOf } from '../crypto/fingerprint';
import type { CryptoAssembly } from '../crypto/keyring';

/**
 * P4 §1 — LE point de construction unique des deux colonnes sensibles d'une
 * revendication : l'empreinte (qui verrouille la ligne) et la valeur chiffrée
 * (qu'on appellera) naissent ENSEMBLE, d'un seul argument. Aucun appelant ne
 * les fabrique séparément — c'est ce qui empêche l'inversion de variables
 * que la base ne peut pas voir (elle n'a pas les clés).
 *
 * Extrait de PhoneService au LOT 5 (étape 7) : l'émancipation déclare une
 * ligne pour une personne SANS compte — même fabrique, pas une deuxième.
 */
export interface PhoneColumns {
  phoneHmac: string;
  hmacKeyId: string;
  phoneEncrypted: string;
  encKeyId: string;
}

export function buildPhoneColumns(crypto: CryptoAssembly, phone: string): PhoneColumns {
  const fingerprint = fingerprintOf(crypto.fingerprint, phone);
  return {
    phoneHmac: fingerprint.value,
    hmacKeyId: fingerprint.hmacKeyId,
    phoneEncrypted: encrypt(crypto.encryption, phone),
    encKeyId: crypto.encryption.activeKeyId,
  };
}

/**
 * Normalisation E.164 minimale — partagée pour la même raison : deux
 * normalisations divergentes feraient deux empreintes pour la même ligne.
 * Le numéro n'existe en clair que dans la pile d'appels, jamais en base ni
 * en log.
 */
export function normalizePhone(raw: string): string | null {
  const trimmed = raw.replace(/[\s().-]/g, '');
  return /^\+[1-9][0-9]{7,14}$/.test(trimmed) ? trimmed : null;
}
