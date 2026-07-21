import { Pool } from 'pg';
import { DB_ERROR, dbErrorCode, isDbError } from '../db/errors';

/**
 * L'OUVERTURE SUR PERSONNE CONNUE (étape 3) : granted_by = 'PROGRAM' pour une
 * personne dont le programme détient l'identifiant public — l'adulte venu au
 * guichet avec le sien, ou l'ayant droit que le programme a lui-même fait
 * naître (le clic lui rend l'identifiant). Aucune responsabilité créée,
 * aucune invitation : le droit, rien que le droit.
 *
 * LES MURS SONT EN BASE (019) : mode accordé exigé pour l'acteur PROGRAM,
 * « ce que la famille a fermé, elle seule le rouvre » (P0110), programme
 * vivant (P0108), au plus un droit ACTIF (index partiel). Ce service rend
 * les refus PROPRES — il ne protège rien.
 *
 * Le pré-contrôle du mode est une FAÇADE (le mur reste 019) : il distingue
 * NOT_GRANTED_MODE de CLOSED_BY_FAMILY sans matcher un texte d'erreur —
 * les deux partagent l'ERRCODE P0110, et un match sur message est interdit.
 */
export type OpenKnownPersonGrantResult =
  | { outcome: 'GRANTED' }
  | { outcome: 'ALREADY_ACTIVE' }
  /** La famille a fermé ce programme : elle seule le rouvre (019). */
  | { outcome: 'CLOSED_BY_FAMILY' }
  | { outcome: 'NOT_GRANTED_MODE' }
  | { outcome: 'NOT_FOUND' }
  | { outcome: 'FORBIDDEN' };

/**
 * La LECTURE (étape 4) — le droit du programme, et RIEN d'autre : jamais les
 * droits d'un autre programme sur la même personne (frontière §7 — le lien
 * inter-programmes ne sort JAMAIS). revoke_reason n'est PAS exposé en
 * lecture (minimisation : le choix de la famille ne se raconte pas ; le
 * chemin d'écriture rend CLOSED_BY_FAMILY quand — et seulement quand — le
 * programme tente de rouvrir).
 */
export type KnownPersonGrantStatus =
  | { outcome: 'OK'; status: 'ACTIVE' | 'REVOKED' | 'NONE'; grantedAt?: string; revokedAt?: string }
  | { outcome: 'NOT_FOUND' };

export type RevokeKnownPersonGrantResult =
  | { outcome: 'REVOKED' }
  /** Aucun droit ACTIF de CE programme : un re-revoke est un constat, pas une erreur. */
  | { outcome: 'NOT_ACTIVE' }
  | { outcome: 'NOT_FOUND' };

export const PROGRAM_GRANTS_SERVICE = 'PROGRAM_GRANTS_SERVICE';

export class ProgramGrantsService {
  constructor(private readonly pool: Pool) {}

  async openForKnownPerson(
    programId: string,
    personIdentifier: string,
  ): Promise<OpenKnownPersonGrantResult> {
    const person = await this.pool.query<{ id: string }>(
      'SELECT id FROM persons WHERE public_identifier = $1',
      [personIdentifier],
    );
    const personId = person.rows[0]?.id;
    if (personId === undefined) {
      // NOT_FOUND EXPLICITE — et pourquoi ce n'est PAS l'accusé uniforme de
      // 012 (distinction doctrinale, validée étape 3, à ne jamais « corriger ») :
      //   · 012 invite par un NUMÉRO — espace petit, énumérable, porteur de
      //     sens, que le programme NE détient PAS : révéler connu/inconnu
      //     serait un oracle d'énumération sur des TIERS → sans oracle,
      //     obligatoire.
      //   · ICI, un IDENTIFIANT CSPRNG (10^10, opaque, sans sémantique) que
      //     le programme détient DÉJÀ (rendu par un clic, ou dicté au
      //     guichet) : c'est une écriture ciblée sur un identifiant
      //     légitimement détenu — le NOT_FOUND est une confirmation
      //     d'intégrité (la faute de frappe du guichet se détecte), pas un
      //     oracle. Deux situations, deux politiques : pas une incohérence.
      return { outcome: 'NOT_FOUND' };
    }

    const program = await this.pool.query<{ access_mode: string }>(
      'SELECT access_mode FROM programs WHERE id = $1',
      [programId],
    );
    if (program.rows[0] === undefined) {
      return { outcome: 'FORBIDDEN' };
    }
    if (program.rows[0].access_mode !== 'GRANTED') {
      return { outcome: 'NOT_GRANTED_MODE' };
    }

    try {
      await this.pool.query(
        `INSERT INTO program_grants (person_id, program_id, granted_by)
         VALUES ($1, $2, 'PROGRAM')`,
        [personId, programId],
      );
      return { outcome: 'GRANTED' };
    } catch (err) {
      if (isActiveGrantCollision(err)) {
        return { outcome: 'ALREADY_ACTIVE' };
      }
      if (isDbError(err, DB_ERROR.ACCESS_MODE_VIOLATION)) {
        // P0110 alors que la façade a déjà tranché le mode : la famille a fermé.
        return { outcome: 'CLOSED_BY_FAMILY' };
      }
      if (isDbError(err, DB_ERROR.DEAD_PARENT)) {
        return { outcome: 'FORBIDDEN' }; // programme retiré du catalogue
      }
      throw err;
    }
  }

  async statusForKnownPerson(
    programId: string,
    personIdentifier: string,
  ): Promise<KnownPersonGrantStatus> {
    const person = await this.pool.query<{ id: string }>(
      'SELECT id FROM persons WHERE public_identifier = $1',
      [personIdentifier],
    );
    const personId = person.rows[0]?.id;
    if (personId === undefined) {
      return { outcome: 'NOT_FOUND' };
    }

    // BOLA de programme AU REGISTRE : program_id = le pid du jeton, posé par
    // le contrôleur — la requête est incapable de toucher un autre programme.
    // Le plus récent au sens de l'ORDRE D'INSERTION (seq, patron 008).
    const grant = await this.pool.query<{
      status: 'ACTIVE' | 'REVOKED';
      granted_at: Date;
      revoked_at: Date | null;
    }>(
      `SELECT g.status, g.granted_at, g.revoked_at FROM program_grants g
        WHERE g.person_id = $1 AND g.program_id = $2
        ORDER BY g.seq DESC LIMIT 1`,
      [personId, programId],
    );
    const row = grant.rows[0];
    if (row === undefined) {
      return { outcome: 'OK', status: 'NONE' };
    }
    return {
      outcome: 'OK',
      status: row.status,
      grantedAt: row.granted_at.toISOString(),
      revokedAt: row.revoked_at?.toISOString(),
    };
  }

  /**
   * La RÉVOCATION par le programme : son droit, motif 'PROGRAM', la matrice
   * de 019 fait le reste (la famille ne rouvrira pas ; le programme, si).
   *
   * 📌 Dette C12, ALIGNÉE ET NON RÉSOLUE (arbitrage étape 4, patron LOT 5) :
   * revoke_reason est DÉCLARATIF dans un GRANT UPDATE — ce service pourrait
   * écrire 'SELF' et maquiller un retrait d'école en choix de famille. Même
   * famille exacte que opened_by/granted_by (C12, LOT 5) : aucune surface
   * d'attaque externe (le rôle applicatif est le seul écrivain, et c'est CE
   * code), mais la preuve de l'acteur au registre attend le LOT prod — une
   * fonction SECURITY DEFINER par acteur, pas un réflexe d'instinct ici.
   */
  async revokeForKnownPerson(
    programId: string,
    personIdentifier: string,
  ): Promise<RevokeKnownPersonGrantResult> {
    const person = await this.pool.query<{ id: string }>(
      'SELECT id FROM persons WHERE public_identifier = $1',
      [personIdentifier],
    );
    const personId = person.rows[0]?.id;
    if (personId === undefined) {
      return { outcome: 'NOT_FOUND' };
    }

    const revoked = await this.pool.query(
      `UPDATE program_grants
          SET status = 'REVOKED', revoke_reason = 'PROGRAM'
        WHERE person_id = $1 AND program_id = $2 AND status = 'ACTIVE'`,
      [personId, programId],
    );
    return revoked.rowCount === 1 ? { outcome: 'REVOKED' } : { outcome: 'NOT_ACTIVE' };
  }
}

function isActiveGrantCollision(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    dbErrorCode(err) === '23505' &&
    'constraint' in err &&
    (err as { constraint?: unknown }).constraint === 'uq_program_grants_active'
  );
}
