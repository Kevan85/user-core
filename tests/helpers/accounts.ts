import { Pool } from 'pg';
import { generatePublicIdentifier } from '../../src/accounts/public-identifier';
import { generateErasureSalt } from '../../src/crypto/person-identity';
import { firstRow } from './db';

// Forme argon2id VALIDE pour le CHECK de 003 — jamais un vrai secret : les
// fixtures qui doivent se connecter passent leur propre hash.
export const FIXTURE_ARGON2ID = '$argon2id$v=19$m=65536,t=3,p=4$Zml4dHVyZQ$c2VjcmV0LWRlLWZpeHR1cmU';

export interface CreateAccountOptions {
  role?: 'ACCOUNT_HOLDER' | 'PLATFORM_STAFF' | 'PLATFORM_ADMIN';
  secretHash?: string;
  isTemporary?: boolean;
  /** Expression timestamptz (ou null) pour l'échéance d'un secret provisoire. */
  expiresAt?: Date | null;
  /**
   * Pour les suites qui posent LEURS propres secrets (003 impose au plus un
   * ACTIVE par compte) : le secret de naissance est retiré juste après.
   */
  retireInitialSecret?: boolean;
  /** Identifiant public de la personne — tiré au CSPRNG par défaut. */
  personIdentifier?: string;
}

/**
 * LA fixture de compte : depuis la migration 011, le rôle applicatif n'a plus
 * AUCUN droit d'insertion dans accounts — create_account() est le chemin
 * unique (réponse au défaut F5 de Scolaria), et les tests l'empruntent comme
 * le service. Depuis 016, un compte de test naît COMPLET : sa PERSONNE, son
 * compte et son premier secret, dans la même transaction.
 */
export async function createAccount(
  pool: Pool,
  identifier: string,
  options: CreateAccountOptions = {},
): Promise<string> {
  const result = await pool.query<{ account_id: string }>(
    `SELECT account_id FROM create_account($1, $2, $3, $4, $5, $6, $7)`,
    [
      identifier,
      options.role ?? 'ACCOUNT_HOLDER',
      options.secretHash ?? FIXTURE_ARGON2ID,
      options.isTemporary ?? false,
      options.expiresAt ?? null,
      options.personIdentifier ?? generatePublicIdentifier(),
      generateErasureSalt(),
    ],
  );
  const accountId = firstRow(result).account_id;
  if (options.retireInitialSecret === true) {
    await pool.query(
      "UPDATE account_secrets SET status = 'RETIRED' WHERE account_id = $1 AND status = 'ACTIVE'",
      [accountId],
    );
  }
  return accountId;
}
