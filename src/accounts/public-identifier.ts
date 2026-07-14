import { randomInt } from 'crypto';

// C4 — l'identifiant public est l'identifiant de CONNEXION. Il sort d'un
// CSPRNG (crypto.randomInt), jamais d'une séquence ni d'un horodatage : un
// identifiant séquentiel ou temporel est énumérable, et toute la surface
// anti-énumération du login (étape 7) deviendrait gratuite à contourner.
//
// L'unicité n'est PAS garantie ici : elle est tranchée par la base
// (uq_accounts_public_identifier). Le chemin d'insertion re-tire sur
// collision, avec un nombre d'essais borné (étape 7).
//
// 10 chiffres sans zéro de tête (chk_accounts_identifier_shape) : lisible et
// dictable au guichet, ~9 × 10⁹ valeurs possibles.
const MIN_INCLUSIVE = 1_000_000_000;
const MAX_INCLUSIVE = 9_999_999_999;

export const PUBLIC_IDENTIFIER_SHAPE = /^[1-9][0-9]{9}$/;

export function generatePublicIdentifier(): string {
  // randomInt : borne haute EXCLUSIVE ; plage ≈ 9 × 10⁹ < 2⁴⁸ (limite de l'API).
  return String(randomInt(MIN_INCLUSIVE, MAX_INCLUSIVE + 1));
}
