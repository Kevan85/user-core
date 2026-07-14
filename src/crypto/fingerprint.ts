import { createHmac, timingSafeEqual } from 'crypto';
import type { FingerprintKey, Keyring } from './keyring';

/**
 * Empreinte déterministe d'une donnée sensible (HMAC-SHA256, clé dédiée).
 *
 * Pourquoi un HMAC et pas un SHA-256 nu : l'espace des numéros congolais est
 * énumérable (quelques dizaines de millions). Un condensat non salé se
 * retrouve par force brute en quelques secondes — l'empreinte serait un
 * pseudonyme réversible, donc de la PII en clair déguisée. La clé rend
 * l'empreinte inattaquable sans elle.
 *
 * L'empreinte est INDEXÉE en base : elle sert l'unicité mondiale et la
 * limitation de débit par ligne. Elle est déterministe POUR UNE CLÉ DONNÉE —
 * d'où hmac_key_id porté en colonne, et l'unicité posée sur le COUPLE
 * (hmac_key_id, empreinte) : sans lui, une rotation ferait cohabiter deux
 * empreintes de la même ligne physique et l'unicité tomberait en silence.
 *
 * Aucune fonction de rotation n'est livrée ici : tourner la clé d'empreinte
 * oblige à déchiffrer et re-hacher toute la PII (CDC §6.1). C'est une
 * migration signée, jamais un appel de fonction.
 */
export interface Fingerprint {
  hmacKeyId: string;
  value: string;
}

export function fingerprintOf(
  keyring: Keyring<FingerprintKey>,
  plaintext: string,
): Fingerprint {
  const key = keyring.active();
  return {
    hmacKeyId: key.keyId,
    value: createHmac('sha256', key.material).update(plaintext, 'utf8').digest('hex'),
  };
}

/**
 * Recalcule l'empreinte sous UNE clé nommée (pas forcément l'active) — le
 * seul usage légitime : vérifier une ligne existante écrite sous une clé
 * antérieure, ou la procédure de rotation elle-même.
 */
export function fingerprintUnder(
  keyring: Keyring<FingerprintKey>,
  hmacKeyId: string,
  plaintext: string,
): Fingerprint | null {
  const key = keyring.get(hmacKeyId);
  if (key === undefined) {
    return null;
  }
  return {
    hmacKeyId,
    value: createHmac('sha256', key.material).update(plaintext, 'utf8').digest('hex'),
  };
}

/** Comparaison à temps constant — une empreinte se compare, elle ne se lit pas. */
export function fingerprintEquals(a: string, b: string): boolean {
  const bufferA = Buffer.from(a, 'utf8');
  const bufferB = Buffer.from(b, 'utf8');
  if (bufferA.length !== bufferB.length) {
    return false;
  }
  return timingSafeEqual(bufferA, bufferB);
}
