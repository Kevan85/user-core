import { Pool } from 'pg';

export interface AccountInvitationView {
  id: string;
  programCode: string;
  programLabel: string;
  invitedAt: string;
  expiresAt: string;
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
  constructor(private readonly pool: Pool) {}

  async list(accountId: string): Promise<AccountInvitationView[]> {
    const result = await this.pool.query<{
      id: string;
      code: string;
      label: string;
      created_at: string;
      expires_at: string;
    }>(
      `SELECT i.id, p.code, p.label, i.created_at, i.expires_at
         FROM phone_claims c
         JOIN program_invitations i
           ON i.hmac_key_id = c.hmac_key_id AND i.phone_hmac = c.phone_hmac
         JOIN programs p ON p.id = i.program_id
        WHERE c.account_id = $1
          AND c.status = 'ACTIVE'
          AND i.status = 'PENDING'
          AND NOT i.suppressed
          AND i.expires_at > now()
        ORDER BY i.created_at`,
      [accountId],
    );
    return result.rows.map((row) => ({
      id: row.id,
      programCode: row.code,
      programLabel: row.label,
      invitedAt: row.created_at,
      expiresAt: row.expires_at,
    }));
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
