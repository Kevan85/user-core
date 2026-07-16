import { Pool } from 'pg';
import type { EncryptedCivilIdentity } from '../../src/crypto/person-identity';
import { generateErasureSalt } from '../../src/crypto/person-identity';
import { firstRow } from './db';

export interface CreatePersonOptions {
  erasureSalt?: Buffer;
  /** Blob produit par encryptCivilIdentity — jamais fabriqué à la main. */
  encrypted?: EncryptedCivilIdentity;
  /**
   * Pose birth_year SANS blob (légal en base : la paire ne lie que le blob et
   * sa clé). Ignoré si `encrypted` est fourni — le module crypto est le seul
   * écrivain de la cohérence blob/année.
   */
  birthYear?: number;
}

/**
 * LA fixture de personne : le rôle applicatif n'a JAMAIS eu de droit d'INSERT
 * sur persons (014) — create_person() est le chemin unique dès le premier
 * jour, et les tests l'empruntent comme le service.
 */
export async function createPerson(
  pool: Pool,
  identifier: string,
  options: CreatePersonOptions = {},
): Promise<string> {
  const salt = options.erasureSalt ?? generateErasureSalt();
  const result = await pool.query<{ id: string }>(
    'SELECT create_person($1, $2, $3, $4, $5) AS id',
    [
      identifier,
      salt,
      options.encrypted?.token ?? null,
      options.encrypted?.encKeyId ?? null,
      options.encrypted?.birthYear ?? options.birthYear ?? null,
    ],
  );
  return firstRow(result).id;
}
