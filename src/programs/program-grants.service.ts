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
      // Compromis DÉCLARÉ (rapport étape 3) : le refus explicite révèle
      // l'existence d'un identifiant — espace 10^10, tirage CSPRNG, débit
      // borné par le mur de l'étape 1 : la sonde est infinitésimale, et
      // l'identifiant est fait pour être DONNÉ (dictable au guichet).
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
