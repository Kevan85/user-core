import { Pool, PoolClient } from 'pg';
import { decrypt } from '../crypto/aes-gcm';
import { fingerprintEquals, fingerprintUnder } from '../crypto/fingerprint';
import type { CryptoAssembly } from '../crypto/keyring';

/**
 * ⚠️⚠️ LE POINT UNIQUE DE DÉCHIFFREMENT D'UN NUMÉRO DANS TOUT LE DÉPÔT.
 *
 * P4 — l'invariant que la base NE PEUT PAS tenir, et le plus dangereux :
 * `phone_hmac` (l'empreinte qui VERROUILLE la ligne) et `phone_encrypted` (la
 * valeur qu'on APPELLERA) sont deux colonnes indépendantes. La base n'a pas
 * les clés — c'est délibéré — donc aucun CHECK, aucun trigger ne peut vérifier
 * qu'elles parlent du même numéro. Une inversion de variables, un refactor
 * malheureux : le registre verrouille la ligne A, et le message part sur le
 * numéro B. Un message de l'écosystème chez un inconnu, sans qu'aucun
 * invariant ne rougisse.
 *
 * La parade ne peut donc pas être une contrainte : c'est une DISCIPLINE. Et une
 * discipline ne tient que si elle est mécanique. D'où :
 *
 *   1. TOUT chemin qui a besoin d'un numéro en clair passe par ICI — le
 *      service du téléphone (ouverture d'une preuve) comme le publisher
 *      (livraison d'un événement). Un deuxième point de déchiffrement avait
 *      déjà réussi à naître (le publisher, F4) et il avait « oublié » la
 *      re-dérivation : la faute se reproduit toute seule, c'est la preuve
 *      qu'elle doit être rendue impossible.
 *   2. Une garde CI vérifie que `decrypt(` n'apparaît NULLE PART hors de
 *      src/crypto/ et de ce fichier. Le prochain point de déchiffrement ne
 *      pourra pas naître en silence.
 *
 * Ici, on RE-DÉRIVE : on déchiffre, on recalcule l'empreinte sous le
 * hmac_key_id de la revendication, et on la compare à celle qui est stockée.
 * Divergence → AUCUNE adresse rendue, alerte, trace. Le mensonge n'atteint
 * jamais un téléphone.
 */
export type AddressResolution =
  | { outcome: 'RESOLVED'; phone: string }
  /** La revendication n'est pas ACTIVE (ligne reprise, révoquée) : rien à joindre. */
  | { outcome: 'NO_ADDRESS' }
  /** Empreinte et valeur chiffrée divergent, ou le jeton est illisible. */
  | { outcome: 'INTEGRITY_VIOLATION' };

interface ClaimFingerprint {
  phone_hmac: string;
  hmac_key_id: string;
}

/**
 * Rend le numéro en clair d'une revendication — et SEULEMENT si tout concorde.
 *
 * @param requireActive true : n'accepte qu'une revendication ACTIVE (livraison
 *        d'un événement — une ligne reprise n'a plus d'adresse, JAMAIS).
 *        false : accepte aussi une revendication PENDING (l'ouverture d'une
 *        preuve de possession, qui est précisément ce qui l'activera).
 */
export async function resolveVerifiedAddress(
  db: Pool | PoolClient,
  crypto: CryptoAssembly,
  claimId: string,
  requireActive: boolean,
): Promise<AddressResolution> {
  const fingerprint = await db.query<ClaimFingerprint>(
    `SELECT phone_hmac, hmac_key_id FROM phone_claims
      WHERE id = $1 ${requireActive ? "AND status = 'ACTIVE'" : ''}`,
    [claimId],
  );
  const claim = fingerprint.rows[0];
  if (claim === undefined) {
    return { outcome: 'NO_ADDRESS' };
  }

  // La valeur chiffrée ne se lit QUE par la fonction dédiée (C9/C10 : la
  // colonne est hors du droit de lecture du rôle applicatif).
  const encrypted = await db.query<{ token: string | null }>(
    requireActive
      ? 'SELECT resolve_notification_address($1) AS token'
      : 'SELECT read_phone_encrypted($1) AS token',
    [claimId],
  );
  const token = encrypted.rows[0]?.token ?? null;
  if (token === null) {
    return { outcome: 'NO_ADDRESS' };
  }

  let phone: string;
  try {
    phone = decrypt(crypto.encryption, token);
  } catch {
    // Clé absente du trousseau, jeton altéré. Jamais le clair, jamais la clé.
    console.error(`INTÉGRITÉ : déchiffrement impossible (claim=${claimId}) — aucun envoi`);
    return { outcome: 'INTEGRITY_VIOLATION' };
  }

  // LA RE-DÉRIVATION. Sans elle, on appellerait un numéro que le registre n'a
  // jamais verrouillé.
  const rederived = fingerprintUnder(crypto.fingerprint, claim.hmac_key_id, phone);
  if (rederived === null || !fingerprintEquals(rederived.value, claim.phone_hmac)) {
    console.error(
      `INTÉGRITÉ : empreinte et valeur chiffrée divergent (claim=${claimId}) — aucun envoi`,
    );
    return { outcome: 'INTEGRITY_VIOLATION' };
  }

  return { outcome: 'RESOLVED', phone };
}
