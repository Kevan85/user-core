import { Pool } from 'pg';
import type { CryptoAssembly } from '../crypto/keyring';
import {
  CivilIdentityIntegrityError,
  decryptCivilIdentity,
} from '../crypto/person-identity';

export interface AccountInvitationView {
  id: string;
  programCode: string;
  programLabel: string;
  invitedAt: string;
  expiresAt: string;
  /**
   * Les ayants droit que l'acceptation rattacherait — NOM D'AFFICHAGE SEUL
   * (étape 5) : jamais les composantes, jamais la date de naissance, jamais
   * un identifiant de personne. Le strict nécessaire pour qu'un vrai parent
   * reconnaisse son enfant. Vide pour une invitation ordinaire.
   */
  dependents: { displayName: string }[];
}

export type InvitationDecisionResult = {
  outcome: 'ACCEPTED' | 'DECLINED' | 'ALREADY_SETTLED' | 'EXPIRED' | 'NOT_FOUND';
};

export const ACCOUNT_INVITATIONS_SERVICE = 'ACCOUNT_INVITATIONS_SERVICE';

const UUID_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Les invitations VUES PAR LE COMPTE (LOT 4). Le rattachement n'a aucun
 * état : une invitation est visible si l'empreinte de la ligne PROUVÉE du
 * compte est celle de l'invitation — un SELECT, rien à nouer à la preuve.
 *
 * Ce que ce service ne décide PAS : qui peut accepter. Le BOLA vit dans
 * accept_program_invitation / decline_program_invitation (012, SECURITY
 * DEFINER) — la revendication ACTIVE sur la ligne est exigée EN BASE. Ici on
 * appelle, on traduit le verdict.
 *
 * LINE_NOT_PROVEN et UNKNOWN se traduisent tous deux NOT_FOUND : pour un
 * appelant qui ne détient pas la ligne, une invitation existante et une
 * invitation inexistante doivent être indiscernables.
 */
export class AccountInvitationsService {
  constructor(
    private readonly pool: Pool,
    private readonly crypto: CryptoAssembly,
  ) {}

  async list(accountId: string): Promise<AccountInvitationView[]> {
    const result = await this.pool.query<{
      id: string;
      code: string;
      label: string;
      created_at: string;
      expires_at: string;
    }>(
      `SELECT i.id, p.code, p.label, i.created_at, i.expires_at
         FROM accounts a
         JOIN phone_claims c ON c.person_id = a.person_id
         JOIN program_invitations i
           ON i.hmac_key_id = c.hmac_key_id AND i.phone_hmac = c.phone_hmac
         JOIN programs p ON p.id = i.program_id
        WHERE a.id = $1
          AND c.status = 'ACTIVE'
          AND i.status = 'PENDING'
          AND NOT i.suppressed
          AND i.expires_at > now()
        ORDER BY i.created_at`,
      [accountId],
    );
    const views: AccountInvitationView[] = [];
    for (const row of result.rows) {
      views.push({
        id: row.id,
        programCode: row.code,
        programLabel: row.label,
        invitedAt: row.created_at,
        expiresAt: row.expires_at,
        dependents: await this.dependentsOf(accountId, row.id),
      });
    }
    return views;
  }

  /**
   * Le NOM D'AFFICHAGE des ayants droit d'une invitation — et RIEN d'autre.
   * Les quatre conditions (PENDING, non supprimée, non expirée, ligne
   * prouvée) vivent EN BASE (022, patron du verdict) : hors d'elles, la
   * fonction rend zéro ligne et ce service n'a rien à décider. Le blob se
   * déchiffre par le point unique (motif F) ; seul displayName en sort —
   * jamais les composantes, jamais la date, jamais un log.
   */
  private async dependentsOf(
    accountId: string,
    invitationId: string,
  ): Promise<{ displayName: string }[]> {
    const rows = await this.pool.query<{
      civil_identity_encrypted: string | null;
      erasure_salt: Buffer;
      birth_year: number | null;
    }>(
      'SELECT civil_identity_encrypted, erasure_salt, birth_year FROM read_invited_dependent_identities($1, $2)',
      [invitationId, accountId],
    );
    const dependents: { displayName: string }[] = [];
    for (const row of rows.rows) {
      if (row.civil_identity_encrypted === null || row.birth_year === null) {
        continue; // théorique : le clic exige l'identité (021, P0111)
      }
      try {
        const identity = decryptCivilIdentity(
          this.crypto.encryption,
          row.erasure_salt,
          row.civil_identity_encrypted,
          row.birth_year,
        );
        dependents.push({ displayName: identity.displayName });
      } catch (err) {
        if (err instanceof CivilIdentityIntegrityError) {
          continue; // l'incident est déjà tracé (C7) — on ne sert pas un registre qui ment
        }
        throw err;
      }
    }
    return dependents;
  }

  async accept(accountId: string, invitationId: string): Promise<InvitationDecisionResult> {
    return this.decide(accountId, invitationId, 'accept_program_invitation');
  }

  async decline(accountId: string, invitationId: string): Promise<InvitationDecisionResult> {
    return this.decide(accountId, invitationId, 'decline_program_invitation');
  }

  private async decide(
    accountId: string,
    invitationId: string,
    fn: 'accept_program_invitation' | 'decline_program_invitation',
  ): Promise<InvitationDecisionResult> {
    // Façade : un id difforme n'est pas une erreur SQL, c'est un inconnu.
    if (!UUID_SHAPE.test(invitationId)) {
      return { outcome: 'NOT_FOUND' };
    }
    const result = await this.pool.query<{ verdict: string }>(
      `SELECT ${fn}($1, $2) AS verdict`,
      [invitationId, accountId],
    );
    switch (result.rows[0]?.verdict) {
      case 'ACCEPTED':
        return { outcome: 'ACCEPTED' };
      case 'DECLINED':
        return { outcome: 'DECLINED' };
      case 'ALREADY_SETTLED':
        return { outcome: 'ALREADY_SETTLED' };
      case 'EXPIRED':
        return { outcome: 'EXPIRED' };
      default:
        // UNKNOWN, LINE_NOT_PROVEN : rien à révéler.
        return { outcome: 'NOT_FOUND' };
    }
  }
}
