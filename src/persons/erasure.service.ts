import { Pool } from 'pg';
import type { LoginThrottle } from '../auth/login-throttle';
import { DB_ERROR, isDbError } from '../db/errors';

export type ErasureState = 'NONE' | 'REQUESTED' | 'RETRACTED' | 'COMPLETED';

export interface ErasureStatus {
  state: ErasureState;
  mode: 'IMMEDIATE' | 'DELAYED' | null;
  /**
   * La fin de la fenêtre de rétractation — la seule date que cette façade
   * expose. La date d'effacement EFFECTIF (J+R) n'existe pas ici : `R` est
   * une inconnue de terrain (CDC §9 n°5, changement d'hébergeur) — aucun
   * délai chiffré ne s'affiche à une famille tant que la valeur effective
   * n'est pas connue.
   */
  effectiveAfter: Date | null;
  retractable: boolean;
}

export type RequestErasureResult =
  | { outcome: 'REQUESTED'; effectiveAfter: Date }
  | { outcome: 'ALREADY_REQUESTED'; effectiveAfter: Date }
  | { outcome: 'COMPLETED' }
  | { outcome: 'ALREADY_ERASED' }
  | { outcome: 'SOLE_RESPONSIBLE' }
  | { outcome: 'ACCOUNT_NOT_ACTIVE' }
  | { outcome: 'THROTTLED' };

export type RetractErasureResult =
  | { outcome: 'RETRACTED' }
  | { outcome: 'WINDOW_CLOSED' }
  | { outcome: 'NOTHING_TO_RETRACT' }
  | { outcome: 'ACCOUNT_NOT_ACTIVE' }
  | { outcome: 'THROTTLED' };

export type StaffEraseResult =
  | { outcome: 'COMPLETED' }
  | { outcome: 'ALREADY_REQUESTED' }
  | { outcome: 'ALREADY_ERASED' }
  | { outcome: 'HAS_ACTIVE_ACCOUNT' }
  | { outcome: 'SOLE_RESPONSIBLE' }
  | { outcome: 'UNKNOWN_PERSON' }
  | { outcome: 'FORBIDDEN' }
  | { outcome: 'THROTTLED' };

export const ERASURE_SERVICE = 'ERASURE_SERVICE';

/**
 * La FAÇADE de l'effacement (étape 5) — elle ne porte AUCUN invariant : les
 * acteurs sont prouvés par le NOM des fonctions de 026, l'ordre et la
 * destruction par les portes de 028, l'échéance par les murs de 026. Ici :
 * des verdicts propres, un throttle (budget dédié, même famille que
 * l'inscription), et le BOLA par construction — l'accountId vient du jeton
 * signé, jamais du corps.
 *
 * Le mode IMMEDIATE s'exécute DANS l'appel (la personne a choisi « tout de
 * suite », l'irréversibilité lui a été énoncée par la façade avant de
 * valider) ; si l'état a changé entre la demande et l'exécution (redevenue
 * dernier responsable), le mur P0114 tranche au commit et la façade traduit.
 */
export class ErasureService {
  constructor(
    private readonly pool: Pool,
    private readonly throttle: LoginThrottle,
  ) {}

  async requestSelf(
    accountId: string,
    mode: 'IMMEDIATE' | 'DELAYED',
  ): Promise<RequestErasureResult> {
    if (!this.throttle.allowByKey(accountId)) {
      return { outcome: 'THROTTLED' };
    }
    const request = await this.pool.query<{ verdict: string; erasure_id: string | null }>(
      'SELECT * FROM request_erasure_self($1, $2)',
      [accountId, mode],
    );
    const verdict = request.rows[0]?.verdict;
    const erasureId = request.rows[0]?.erasure_id ?? null;

    switch (verdict) {
      case 'REQUESTED': {
        if (erasureId === null) {
          throw new Error('effacement : REQUESTED sans identifiant de demande');
        }
        if (mode === 'IMMEDIATE') {
          return this.execute(erasureId);
        }
        return { outcome: 'REQUESTED', effectiveAfter: await this.effectiveAfterOf(erasureId) };
      }
      case 'ALREADY_REQUESTED': {
        if (erasureId === null) {
          throw new Error('effacement : ALREADY_REQUESTED sans identifiant de demande');
        }
        return {
          outcome: 'ALREADY_REQUESTED',
          effectiveAfter: await this.effectiveAfterOf(erasureId),
        };
      }
      case 'ALREADY_ERASED':
        return { outcome: 'ALREADY_ERASED' };
      case 'SOLE_RESPONSIBLE':
        return { outcome: 'SOLE_RESPONSIBLE' };
      case 'ACCOUNT_NOT_ACTIVE':
        return { outcome: 'ACCOUNT_NOT_ACTIVE' };
      default:
        // UNKNOWN_ACCOUNT : un jeton signé désigne toujours un compte réel —
        // l'absence est une incohérence franche, pas un cas métier.
        throw new Error(`effacement : verdict inattendu « ${verdict ?? 'aucun'} »`);
    }
  }

  async retractSelf(accountId: string): Promise<RetractErasureResult> {
    if (!this.throttle.allowByKey(accountId)) {
      return { outcome: 'THROTTLED' };
    }
    const result = await this.pool.query<{ verdict: string }>(
      'SELECT * FROM retract_erasure_self($1)',
      [accountId],
    );
    const verdict = result.rows[0]?.verdict;
    switch (verdict) {
      case 'RETRACTED':
        return { outcome: 'RETRACTED' };
      case 'WINDOW_CLOSED':
        return { outcome: 'WINDOW_CLOSED' };
      case 'NOTHING_TO_RETRACT':
        return { outcome: 'NOTHING_TO_RETRACT' };
      case 'ACCOUNT_NOT_ACTIVE':
        return { outcome: 'ACCOUNT_NOT_ACTIVE' };
      default:
        throw new Error(`effacement : verdict inattendu « ${verdict ?? 'aucun'} »`);
    }
  }

  /** L'état courant — la DERNIÈRE demande fait foi (seq, jamais l'horloge). */
  async status(accountId: string): Promise<ErasureStatus> {
    const result = await this.pool.query<{
      status: 'REQUESTED' | 'RETRACTED' | 'COMPLETED';
      mode: 'IMMEDIATE' | 'DELAYED';
      effective_after: Date;
      retractable: boolean;
    }>(
      `SELECT e.status, e.mode, e.effective_after,
              (e.status = 'REQUESTED' AND e.mode = 'DELAYED'
               AND now() < e.effective_after) AS retractable
         FROM accounts a
         JOIN person_erasures e ON e.person_id = a.person_id
        WHERE a.id = $1
        ORDER BY e.seq DESC
        LIMIT 1`,
      [accountId],
    );
    const row = result.rows[0];
    if (row === undefined) {
      return { state: 'NONE', mode: null, effectiveAfter: null, retractable: false };
    }
    return {
      state: row.status,
      mode: row.mode,
      effectiveAfter: row.effective_after,
      retractable: row.retractable,
    };
  }

  async eraseByStaff(actorAccountId: string, personPublicIdentifier: string): Promise<StaffEraseResult> {
    if (!this.throttle.allowByKey(actorAccountId)) {
      return { outcome: 'THROTTLED' };
    }
    const person = await this.pool.query<{ id: string }>(
      'SELECT id FROM persons WHERE public_identifier = $1',
      [personPublicIdentifier],
    );
    const personId = person.rows[0]?.id;
    if (personId === undefined) {
      return { outcome: 'UNKNOWN_PERSON' };
    }

    const request = await this.pool.query<{ verdict: string; erasure_id: string | null }>(
      'SELECT * FROM request_erasure_staff($1, $2)',
      [actorAccountId, personId],
    );
    const verdict = request.rows[0]?.verdict;
    const erasureId = request.rows[0]?.erasure_id ?? null;
    switch (verdict) {
      case 'REQUESTED': {
        if (erasureId === null) {
          throw new Error('effacement : REQUESTED sans identifiant de demande');
        }
        const executed = await this.execute(erasureId);
        // Le chemin staff est IMMEDIATE par construction (G1) : l'exécution
        // rend COMPLETED ou traduit le mur — jamais un état intermédiaire.
        return executed.outcome === 'COMPLETED' ? executed : { outcome: 'SOLE_RESPONSIBLE' };
      }
      case 'ALREADY_REQUESTED':
        // Une demande self DELAYED, née avant la désactivation du compte,
        // court encore : elle s'exécutera à SON échéance — le staff n'écrase
        // pas une décision de la personne.
        return { outcome: 'ALREADY_REQUESTED' };
      case 'ALREADY_ERASED':
        return { outcome: 'ALREADY_ERASED' };
      case 'HAS_ACTIVE_ACCOUNT':
        return { outcome: 'HAS_ACTIVE_ACCOUNT' };
      case 'SOLE_RESPONSIBLE':
        return { outcome: 'SOLE_RESPONSIBLE' };
      case 'FORBIDDEN':
        return { outcome: 'FORBIDDEN' };
      default:
        throw new Error(`effacement : verdict inattendu « ${verdict ?? 'aucun'} »`);
    }
  }

  /** IMMEDIATE : l'exécution vit dans l'appel — le mur P0114 peut encore trancher. */
  private async execute(erasureId: string): Promise<{ outcome: 'COMPLETED' | 'SOLE_RESPONSIBLE' }> {
    try {
      const result = await this.pool.query<{ verdict: string }>('SELECT * FROM erase_person($1)', [
        erasureId,
      ]);
      if (result.rows[0]?.verdict !== 'COMPLETED') {
        throw new Error(
          `effacement : exécution immédiate inaboutie (${result.rows[0]?.verdict ?? 'aucun verdict'})`,
        );
      }
      return { outcome: 'COMPLETED' };
    } catch (err) {
      // La course réelle : redevenu dernier responsable entre la demande et
      // l'exécution. Le mur a tranché ; la demande reste enregistrée.
      if (isDbError(err, DB_ERROR.ORPHANED_DEPENDENT)) {
        return { outcome: 'SOLE_RESPONSIBLE' };
      }
      throw err;
    }
  }

  private async effectiveAfterOf(erasureId: string): Promise<Date> {
    const result = await this.pool.query<{ effective_after: Date }>(
      'SELECT effective_after FROM person_erasures WHERE id = $1',
      [erasureId],
    );
    const row = result.rows[0];
    if (row === undefined) {
      throw new Error('effacement : demande introuvable après écriture');
    }
    return row.effective_after;
  }
}
