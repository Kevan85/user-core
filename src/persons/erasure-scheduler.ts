import { Pool } from 'pg';
import { DB_ERROR, dbErrorCode } from '../db/errors';

export interface ErasureTickReport {
  /** Préavis déposés dans l'outbox ce tour-ci. */
  noticed: number;
  /** Effacements exécutés (crypto-destruction accomplie). */
  executed: number;
  /**
   * Refus du MUR du dernier responsable (P0114) — un état métier ATTENDU,
   * dont la sortie est un acte staff. Jamais confondu avec une panne.
   */
  blocked: number;
  /**
   * Tout le reste : interblocage, connexion coupée, bug — une PANNE à
   * investiguer. Un humain formé à voir passer `blocked` ne doit jamais
   * apprendre à ignorer celle-ci (G2).
   */
  failed: number;
}

/**
 * Le chemin DIFFÉRÉ de l'effacement (étape 4) — un balayage, deux gestes,
 * zéro plomberie neuve (CDC §10 n°14) :
 *
 *   · à J-48 h (paramètre erasure_policy), le PRÉAVIS : record_erasure_notice
 *     écrit l'outbox, le publisher existant dépose dans le compte ;
 *   · à l'échéance, l'EXÉCUTION : erase_person(), dont l'idempotence est EN
 *     BASE (verdicts ALREADY_COMPLETED / RETRACTED / NOT_DUE — jamais une
 *     exception de rejeu). Ce fichier n'en refait aucune.
 *
 * Un mur qui refuse l'exécution (P0114 : la personne est redevenue dernier
 * responsable entre la demande et l'échéance) devient un VERDICT COMPTÉ et
 * une trace sans PII — jamais une panne muette et répétée. La demande reste
 * REQUESTED : la sortie de cet état est un acte staff (désigner un
 * remplaçant), pas un retry.
 */
export class ErasureScheduler {
  constructor(private readonly pool: Pool) {}

  async tick(): Promise<ErasureTickReport> {
    const report: ErasureTickReport = { noticed: 0, executed: 0, blocked: 0, failed: 0 };

    // WHERE notified_at IS NULL est OBLIGATOIRE : le set-once de 026 LÈVE
    // (P0104) sur un second passage, il ne no-ope pas. Le filtre évite la
    // boucle d'exceptions ; la fonction re-vérifie SOUS VERROU (029) — c'est
    // elle le mur, ce filtre n'est qu'une économie de rejeu.
    const notices = await this.pool.query<{ id: string }>(
      `SELECT id FROM person_erasures
        WHERE status = 'REQUESTED'
          AND mode = 'DELAYED'
          AND notified_at IS NULL
          AND now() >= effective_after
                      - make_interval(hours => erasure_notification_lead_hours())
        ORDER BY effective_after`,
    );
    // Pas de LIMIT, et c'est un CHOIX (G3) : une demande d'effacement est un
    // acte humain, rare par nature — le backlog d'un tick se compte en unités,
    // pas en milliers. Le jour où un lot borné devient nécessaire, le patron
    // existe déjà (claim_outbox_batch) ; on ne le copie pas « au cas où ».
    for (const notice of notices.rows) {
      const result = await this.pool.query<{ verdict: string }>(
        'SELECT * FROM record_erasure_notice($1)',
        [notice.id],
      );
      if (result.rows[0]?.verdict === 'NOTICED') {
        report.noticed += 1;
      }
    }

    const due = await this.pool.query<{ id: string }>(
      `SELECT id FROM person_erasures
        WHERE status = 'REQUESTED' AND now() >= effective_after
        ORDER BY effective_after`,
    );
    for (const erasure of due.rows) {
      try {
        const result = await this.pool.query<{ verdict: string }>('SELECT * FROM erase_person($1)', [
          erasure.id,
        ]);
        if (result.rows[0]?.verdict === 'COMPLETED') {
          report.executed += 1;
        }
      } catch (err) {
        // G2 — un MUR n'est pas une PANNE, et les confondre tue le canal :
        // `blocked` est un état normal qu'un humain apprend à voir passer —
        // une vraie panne cachée derrière ce compteur ne serait jamais
        // investiguée. Zéro PII des deux côtés : code, nom, UUID technique.
        if (dbErrorCode(err) === DB_ERROR.ORPHANED_DEPENDENT) {
          report.blocked += 1;
          console.error(
            `effacement : refusé par le mur du dernier responsable (P0114) — demande ${erasure.id} — un remplaçant (acte staff) est attendu`,
          );
        } else {
          report.failed += 1;
          const label = dbErrorCode(err) ?? (err instanceof Error ? err.name : 'inconnue');
          console.error(
            `effacement : PANNE d'exécution (${label}) — demande ${erasure.id} — à investiguer, ce n'est PAS un refus métier`,
          );
        }
      }
    }

    return report;
  }
}
