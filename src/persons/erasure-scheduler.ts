import { Pool } from 'pg';
import { dbErrorCode } from '../db/errors';

export interface ErasureTickReport {
  /** Préavis déposés dans l'outbox ce tour-ci. */
  noticed: number;
  /** Effacements exécutés (crypto-destruction accomplie). */
  executed: number;
  /** Exécutions refusées par un mur (P0114 en tête) : comptées, jamais muettes. */
  blocked: number;
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
    const report: ErasureTickReport = { noticed: 0, executed: 0, blocked: 0 };

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
        report.blocked += 1;
        // Zéro PII : un code d'erreur et l'UUID technique de la DEMANDE.
        console.error(
          `effacement : exécution bloquée (${dbErrorCode(err) ?? 'inconnue'}) — demande ${erasure.id}`,
        );
      }
    }

    return report;
  }
}
