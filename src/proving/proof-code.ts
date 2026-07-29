import { createHmac, randomInt, timingSafeEqual } from 'crypto';
import type { ProofCodeKeyring } from '../crypto/keyring';

/**
 * Le code de possession : généré par le cœur (CSPRNG), livré par le
 * fournisseur, et conservé UNIQUEMENT sous forme de HMAC (P1).
 *
 * Pourquoi un HMAC à clé dédiée, et pas un SHA-256 : un code à 6 chiffres vit
 * dans un espace de 10⁶. Un condensat non salé se retourne par force brute en
 * quelques secondes — le « hash » serait le code lui-même, en clair, avec un
 * chapeau. La clé rend le condensat inattaquable sans elle.
 *
 * Le trousseau (le TROISIÈME — trois usages, trois cycles de vie) est assemblé
 * au point unique src/crypto/keyring.ts, comme les trois autres : la garde CI
 * du motif H refuse qu'un trousseau soit parsé ailleurs. Ce fichier ne fait
 * que s'en SERVIR.
 */
export { assembleProofCodeKeyring } from '../crypto/keyring';
export type { ProofCodeKeyring } from '../crypto/keyring';

/**
 * Le code lui-même : CSPRNG, longueur en CONFIG (jamais figée — un opérateur
 * ou un régulateur peut l'imposer différente ; CDC §9 : on paramètre).
 */
export function generateProofCode(digits: number): string {
  if (!Number.isInteger(digits) || digits < 4 || digits > 10) {
    throw new Error(`longueur de code invalide : ${digits}`);
  }
  let code = '';
  for (let i = 0; i < digits; i++) {
    code += String(randomInt(0, 10));
  }
  return code;
}

export interface HashedCode {
  keyId: string;
  hmac: string;
}

export function hashProofCode(keyring: ProofCodeKeyring, code: string): HashedCode {
  const material = keyring.keys.get(keyring.activeKeyId);
  if (material === undefined) {
    throw new Error('trousseau des codes : clé active absente (config validée au boot)');
  }
  return {
    keyId: keyring.activeKeyId,
    hmac: createHmac('sha256', material).update(code, 'utf8').digest('hex'),
  };
}

/** Recalcule sous une clé NOMMÉE — le code présenté se compare à la ligne écrite. */
export function hashProofCodeUnder(
  keyring: ProofCodeKeyring,
  keyId: string,
  code: string,
): string | null {
  const material = keyring.keys.get(keyId);
  if (material === undefined) {
    return null;
  }
  return createHmac('sha256', material).update(code, 'utf8').digest('hex');
}

export function codeHashEquals(a: string, b: string): boolean {
  const bufferA = Buffer.from(a, 'utf8');
  const bufferB = Buffer.from(b, 'utf8');
  return bufferA.length === bufferB.length && timingSafeEqual(bufferA, bufferB);
}
