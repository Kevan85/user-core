import { Pool } from 'pg';
import { DB_ERROR, isDbError } from '../db/errors';

export interface ProgramView {
  code: string;
  label: string;
  accessMode: 'SELF_SERVICE' | 'GRANTED';
  /** Le compte y a-t-il accès, à cet instant ? Rien d'autre. */
  activated: boolean;
}

export type ActivateResult =
  | { outcome: 'ACTIVATED' }
  | { outcome: 'ALREADY_ACTIVE' }
  | { outcome: 'NOT_SELF_SERVICE' }
  | { outcome: 'REVOKED_BY_THIRD_PARTY' }
  | { outcome: 'UNKNOWN_PROGRAM' };

export type DeactivateResult =
  | { outcome: 'DEACTIVATED' }
  | { outcome: 'NOT_ACTIVE' }
  | { outcome: 'UNKNOWN_PROGRAM' };

export type StaffGrantResult =
  | { outcome: 'GRANTED' }
  | { outcome: 'ALREADY_ACTIVE' }
  | { outcome: 'FORBIDDEN' }
  | { outcome: 'UNKNOWN_PROGRAM' }
  | { outcome: 'UNKNOWN_ACCOUNT' };

export const CATALOG_SERVICE = 'CATALOG_SERVICE';

/**
 * Le catalogue : ce que la famille a ACTIVÉ, et rien de plus.
 *
 * FRONTIÈRE (CLAUDE.md §7, CDC §2.2) : User-Core sait qu'un programme est
 * activé. Il ne sait pas ce que le compte y FAIT — pas d'élève, pas de
 * facture, pas d'échéance. Le catalogue est un DROIT D'ACCÈS, jamais un
 * moteur d'abonnement.
 *
 * Ce que le service NE décide PAS : qui peut ouvrir quoi. Le mode d'accès du
 * programme et la règle de réactivation vivent EN BASE (008) — un service se
 * réécrit, une contrainte de base ne se contourne pas en silence. Ici, on
 * appelle, et on traduit le refus de la base en réponse HTTP.
 */
export class CatalogService {
  constructor(private readonly pool: Pool) {}

  /**
   * Le catalogue vu par un compte : chaque programme, activé ou non — pour SA
   * personne (019 : le droit appartient à la personne ; le compte le gère).
   */
  async list(accountId: string): Promise<ProgramView[]> {
    const result = await this.pool.query<{
      code: string;
      label: string;
      access_mode: 'SELF_SERVICE' | 'GRANTED';
      activated: boolean;
    }>(
      `SELECT p.code, p.label, p.access_mode,
              EXISTS (SELECT 1 FROM program_grants g
                       JOIN accounts a ON a.person_id = g.person_id
                       WHERE g.program_id = p.id
                         AND a.id = $1
                         AND g.status = 'ACTIVE') AS activated
         FROM programs p
        WHERE p.status = 'ACTIVE'
        ORDER BY p.code`,
      [accountId],
    );
    return result.rows.map((row) => ({
      code: row.code,
      label: row.label,
      accessMode: row.access_mode,
      activated: row.activated,
    }));
  }

  /** La famille active un programme POUR ELLE-MÊME (BOLA : accountId du jeton). */
  async activate(accountId: string, code: string): Promise<ActivateResult> {
    const program = await this.findProgram(code);
    if (program === null) {
      return { outcome: 'UNKNOWN_PROGRAM' };
    }
    const personId = await this.personOf(accountId);
    try {
      await this.pool.query(
        "INSERT INTO program_grants (person_id, program_id, granted_by) VALUES ($1, $2, 'SELF')",
        [personId, program.id],
      );
      return { outcome: 'ACTIVATED' };
    } catch (err) {
      if (isDbError(err, DB_ERROR.ACCESS_MODE_VIOLATION)) {
        // La base a tranché : soit le programme ne s'ouvre pas soi-même, soit
        // un TIERS a retiré cet accès et la famille ne peut pas le rouvrir.
        // On distingue les deux pour le message, jamais pour la décision.
        const previous = await this.lastGrant(personId, program.id);
        return previous === null
          ? { outcome: 'NOT_SELF_SERVICE' }
          : { outcome: 'REVOKED_BY_THIRD_PARTY' };
      }
      if (this.isUniqueViolation(err, 'uq_program_grants_active')) {
        return { outcome: 'ALREADY_ACTIVE' };
      }
      throw err;
    }
  }

  /**
   * La famille désactive — TOUJOURS possible, même sur un programme qu'un
   * tiers lui a ouvert. C'est son compte : elle retire le programme de son
   * écran ; le tiers garde ses propres données de son côté.
   */
  async deactivate(accountId: string, code: string): Promise<DeactivateResult> {
    const program = await this.findProgram(code);
    if (program === null) {
      return { outcome: 'UNKNOWN_PROGRAM' };
    }
    // BOLA : la jointure par SA personne est la ceinture — un compte ne coupe
    // que le sien, même en nommant le programme d'un autre.
    const result = await this.pool.query(
      `UPDATE program_grants SET status = 'REVOKED', revoke_reason = 'SELF'
        WHERE person_id = (SELECT person_id FROM accounts WHERE id = $1)
          AND program_id = $2 AND status = 'ACTIVE'`,
      [accountId, program.id],
    );
    return result.rowCount === 0 ? { outcome: 'NOT_ACTIVE' } : { outcome: 'DEACTIVATED' };
  }

  /**
   * Le staff ouvre un programme pour un compte (mode GRANTED : c'est l'école
   * qui inscrit). En LOT 3, c'est le SEUL chemin d'ouverture d'un programme
   * accordé — l'identité cliente des programmes (acteur PROGRAM) arrive au
   * LOT 4, et l'énumération l'attend déjà.
   */
  async grantAsStaff(
    actorAccountId: string,
    targetAccountId: string,
    code: string,
  ): Promise<StaffGrantResult> {
    const actorRole = await this.roleOf(actorAccountId);
    if (actorRole !== 'PLATFORM_STAFF' && actorRole !== 'PLATFORM_ADMIN') {
      return { outcome: 'FORBIDDEN' };
    }
    const program = await this.findProgram(code);
    if (program === null) {
      return { outcome: 'UNKNOWN_PROGRAM' };
    }
    if ((await this.roleOf(targetAccountId)) === null) {
      return { outcome: 'UNKNOWN_ACCOUNT' };
    }
    try {
      await this.pool.query(
        `INSERT INTO program_grants (person_id, program_id, granted_by)
         VALUES ((SELECT person_id FROM accounts WHERE id = $1), $2, 'PLATFORM_STAFF')`,
        [targetAccountId, program.id],
      );
      return { outcome: 'GRANTED' };
    } catch (err) {
      if (this.isUniqueViolation(err, 'uq_program_grants_active')) {
        return { outcome: 'ALREADY_ACTIVE' };
      }
      throw err;
    }
  }

  private async findProgram(code: string): Promise<{ id: string } | null> {
    const result = await this.pool.query<{ id: string }>(
      "SELECT id FROM programs WHERE code = $1 AND status = 'ACTIVE'",
      [code],
    );
    return result.rows[0] ?? null;
  }

  private async roleOf(accountId: string): Promise<string | null> {
    const result = await this.pool.query<{ role: string }>(
      "SELECT role FROM accounts WHERE id = $1 AND status = 'ACTIVE'",
      [accountId],
    );
    return result.rows[0]?.role ?? null;
  }

  private async lastGrant(personId: string, programId: string): Promise<{ id: string } | null> {
    const result = await this.pool.query<{ id: string }>(
      // Ordre d'INSERTION (seq), jamais l'horloge : now() est l'horodatage de
      // la transaction, deux lignes d'une même transaction sont ex æquo (F3).
      `SELECT id FROM program_grants
        WHERE person_id = $1 AND program_id = $2
        ORDER BY seq DESC LIMIT 1`,
      [personId, programId],
    );
    return result.rows[0] ?? null;
  }

  private async personOf(accountId: string): Promise<string> {
    const result = await this.pool.query<{ person_id: string }>(
      'SELECT person_id FROM accounts WHERE id = $1',
      [accountId],
    );
    const row = result.rows[0];
    if (row === undefined) {
      throw new Error('catalogue : compte introuvable');
    }
    return row.person_id;
  }

  private isUniqueViolation(err: unknown, constraint: string): boolean {
    return (
      typeof err === 'object' &&
      err !== null &&
      'code' in err &&
      (err as { code?: unknown }).code === '23505' &&
      'constraint' in err &&
      (err as { constraint?: unknown }).constraint === constraint
    );
  }
}
