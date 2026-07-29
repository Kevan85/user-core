import { createHmac } from 'crypto';
import type { ReferenceKeyring } from '../crypto/keyring';

/**
 * Les RÉFÉRENCES d'idempotence des programmes (021).
 *
 * La référence arrive EN CLAIR dans le payload /v1 ; le service calcule son
 * empreinte ICI et ne stocke JAMAIS la valeur (elle peut porter de la PII :
 * rien n'empêche un programme d'y mettre un nom). Elle ne doit JAMAIS
 * apparaître dans un log — §3.2 : counts, UUID, verdicts, rien d'autre.
 *
 * Pourquoi un HMAC et pas un SHA-256 nu : une référence devinable (un
 * matricule court, un nom) se retrouve au dictionnaire — le condensat serait
 * la valeur en clair avec un chapeau (même argument que P1, les codes).
 *
 * Le trousseau (le QUATRIÈME — cycle de vie distinct, doctrine 006) est
 * assemblé au point unique src/crypto/keyring.ts, comme les trois autres :
 * la garde CI du motif H refuse qu'un trousseau soit parsé ailleurs. Sa
 * rotation reste une procédure exceptionnelle dont la conséquence est
 * déclarée en 021 : l'idempotence ne traverse pas une rotation.
 */
export { assembleReferenceKeyring } from '../crypto/keyring';
export type { ReferenceKeyring } from '../crypto/keyring';

export interface HashedReference {
  keyId: string;
  hmac: string;
}

export function hashReference(keyring: ReferenceKeyring, reference: string): HashedReference {
  const material = keyring.keys.get(keyring.activeKeyId);
  if (material === undefined) {
    throw new Error('trousseau des références : clé active absente (config validée au boot)');
  }
  return {
    keyId: keyring.activeKeyId,
    hmac: createHmac('sha256', material).update(reference, 'utf8').digest('hex'),
  };
}

/**
 * (024) L'empreinte de la MÊME référence sous CHAQUE clé du trousseau — la
 * recherche d'idempotence les couvre toutes : un re-clic reconnaît sa
 * référence même écrite sous une clé antérieure. L'écriture, elle, reste à
 * la clé active (hashReference). Tableaux parallèles, la paire active
 * comprise — la fonction SQL refuse toute autre forme (fail-closed).
 */
export function hashReferenceUnderAll(
  keyring: ReferenceKeyring,
  reference: string,
): { keyIds: string[]; hmacs: string[] } {
  const keyIds: string[] = [];
  const hmacs: string[] = [];
  for (const [keyId, material] of keyring.keys) {
    keyIds.push(keyId);
    hmacs.push(createHmac('sha256', material).update(reference, 'utf8').digest('hex'));
  }
  return { keyIds, hmacs };
}
