import { Pool } from 'pg';
import type { CryptoAssembly } from '../crypto/keyring';
import {
  CivilIdentityError,
  CivilIdentityIntegrityError,
  decryptCivilIdentity,
  encryptCivilIdentity,
  type PersonCivilIdentity,
} from '../crypto/person-identity';
import { DB_ERROR, isDbError } from '../db/errors';

export type ReadIdentityResult =
  | { outcome: 'OK'; identity: PersonCivilIdentity }
  | { outcome: 'NOT_PROVIDED' }
  /** Le registre se contredit (C4) : incident d'intégrité, JAMAIS un 400. */
  | { outcome: 'INTEGRITY_VIOLATION' };

export type ProvideIdentityResult =
  | { outcome: 'OK'; identity: PersonCivilIdentity }
  | { outcome: 'INVALID'; reason: string }
  /** La date fournie change l'année posée : set-once en base (P0101). */
  | { outcome: 'BIRTH_DATE_LOCKED' };

export const IDENTITY_SERVICE = 'IDENTITY_SERVICE';

/**
 * L'identité d'état civil de la personne DU COMPTE (LOT 5, étape 3) — le
 * premier appelant du blob chiffré de 014.
 *
 * BOLA : l'accountId vient du jeton signé ; on n'atteint JAMAIS une autre
 * personne que celle du compte. Zéro log ici (un nom, une date : PII) — la
 * seule trace qui existe est la trace d'INTÉGRITÉ, émise sans PII par le
 * module crypto lui-même (C7).
 *
 * Fournir son identité est permis tant que l'ANNÉE ne change pas : corriger
 * une faute de frappe dans un nom, oui ; changer d'année de naissance, non —
 * le set-once de 014 est le mur, ce service rend l'erreur propre (§3.1).
 */
export class IdentityService {
  constructor(
    private readonly pool: Pool,
    private readonly crypto: CryptoAssembly,
  ) {}

  async read(accountId: string): Promise<ReadIdentityResult> {
    const stored = await this.readStored(accountId);
    if (stored.civil_identity_encrypted === null || stored.birth_year === null) {
      return { outcome: 'NOT_PROVIDED' };
    }
    try {
      const identity = decryptCivilIdentity(
        this.crypto.encryption,
        stored.erasure_salt,
        stored.civil_identity_encrypted,
        stored.birth_year,
      );
      return { outcome: 'OK', identity };
    } catch (err) {
      // Divergence blob/borne d'âge, blob illisible, clé absente : le
      // registre ment sur lui-même. La trace est déjà émise au point de
      // détection ; ici on rend un verdict DISTINCT du 400.
      if (err instanceof CivilIdentityIntegrityError) {
        return { outcome: 'INTEGRITY_VIOLATION' };
      }
      throw err;
    }
  }

  async provide(accountId: string, identity: PersonCivilIdentity): Promise<ProvideIdentityResult> {
    const stored = await this.readStored(accountId);

    let encrypted;
    try {
      encrypted = encryptCivilIdentity(this.crypto.encryption, stored.erasure_salt, identity);
    } catch (err) {
      if (err instanceof CivilIdentityError) {
        // Les messages du module sont garantis sans PII : relayables.
        return { outcome: 'INVALID', reason: err.message };
      }
      throw err;
    }

    try {
      await this.pool.query(
        `UPDATE persons
            SET civil_identity_encrypted = $2, enc_key_id = $3, birth_year = $4
          WHERE id = $1`,
        [stored.person_id, encrypted.token, encrypted.encKeyId, encrypted.birthYear],
      );
    } catch (err) {
      if (isDbError(err, DB_ERROR.IMMUTABLE)) {
        return { outcome: 'BIRTH_DATE_LOCKED' };
      }
      throw err;
    }
    return { outcome: 'OK', identity };
  }

  // Le blob et le sel ne se lisent QUE par la fonction dédiée (014) : le rôle
  // applicatif n'a pas le droit de lecture directe, et c'est voulu.
  private async readStored(accountId: string): Promise<{
    person_id: string;
    civil_identity_encrypted: string | null;
    enc_key_id: string | null;
    erasure_salt: Buffer;
    birth_year: number | null;
  }> {
    const result = await this.pool.query<{
      person_id: string;
      civil_identity_encrypted: string | null;
      enc_key_id: string | null;
      erasure_salt: Buffer;
      birth_year: number | null;
    }>(
      `SELECT a.person_id, r.civil_identity_encrypted, r.enc_key_id, r.erasure_salt, r.birth_year
         FROM accounts a, LATERAL read_person_identity(a.person_id) r
        WHERE a.id = $1`,
      [accountId],
    );
    const row = result.rows[0];
    if (row === undefined) {
      // Un jeton signé désigne toujours un compte réel : l'absence est une
      // incohérence franche, pas un cas métier.
      throw new Error('identité civile : compte introuvable');
    }
    return row;
  }
}
