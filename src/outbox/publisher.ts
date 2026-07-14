import { Pool } from 'pg';
import { decrypt } from '../crypto/aes-gcm';
import type { CryptoAssembly } from '../crypto/keyring';
import {
  OutboundFailed,
  type OutboundChannel,
  type OutboundDispatcher,
} from '../dispatch/outbound-dispatcher';

export interface PublisherConfig {
  batchSize: number;
  leaseSeconds: number;
  maxAttempts: number;
  backoffBaseSeconds: number;
  backoffCapSeconds: number;
}

interface OutboxRow {
  id: string;
  event_type: string;
  account_id: string;
  claim_id: string | null;
  attempts: number;
}

interface Policy {
  allowed_channels: OutboundChannel[];
  in_account: boolean;
}

export interface DrainReport {
  claimed: number;
  published: number;
  retried: number;
  failed: number;
  /** Événements sans aucun canal permis : le silence, tracé. */
  notNotifiable: number;
}

/**
 * LE publisher de l'outbox — UN seul, patron payment-core.
 *
 * Ce qu'il est : un mécanisme de FIABILITÉ. Il garantit qu'un événement écrit
 * dans la transaction métier finit par sortir (ou meurt bruyamment).
 *
 * Ce qu'il n'est PAS, et ne deviendra jamais (CLAUDE.md §3.12) : un broker.
 * Pas de topics, pas de routage, pas d'offsets par consommateur, pas de replay
 * sélectif, pas de dead-letter par consommateur. Le besoin de l'un d'eux
 * serait le signal d'introduire un vrai broker — pas d'enrichir ceci.
 *
 * §3.13 : on réserve un lot (transaction), on COMMIT, on appelle le
 * dispatcher HORS transaction, on écrit le verdict dans une transaction
 * neuve. Un réseau qui met trente secondes à répondre ne tient jamais une
 * transaction ouverte.
 *
 * ⚠️ LE PIÈGE DU RECYCLAGE, côté service : ce fichier ne décide RIEN. La
 * politique de canal vit en base (event_channel_policy), et la résolution
 * d'adresse REFUSE une revendication non ACTIVE — donc l'événement de reprise
 * de ligne n'a, par construction, aucune adresse externe à viser. Si un jour
 * quelqu'un réécrit ce publisher en oubliant la règle, la base la tiendra
 * quand même.
 */
export class OutboxPublisher {
  constructor(
    private readonly pool: Pool,
    private readonly dispatcher: OutboundDispatcher,
    private readonly crypto: CryptoAssembly,
    private readonly config: PublisherConfig,
  ) {}

  async drain(): Promise<DrainReport> {
    const report: DrainReport = {
      claimed: 0,
      published: 0,
      retried: 0,
      failed: 0,
      notNotifiable: 0,
    };

    const batch = await this.pool.query<OutboxRow>('SELECT * FROM claim_outbox_batch($1, $2)', [
      this.config.batchSize,
      this.config.leaseSeconds,
    ]);
    report.claimed = batch.rows.length;

    for (const event of batch.rows) {
      const policy = await this.policyFor(event.event_type);
      const address = await this.resolveAddress(event.claim_id);

      // Aucun canal externe permis (ou aucune adresse joignable — la ligne a
      // été reprise) : on dépose la notification dans le compte si la
      // politique le prévoit, sinon on ne notifie pas, et on le TRACE.
      const externalChannel = this.pickChannel(policy, address);

      if (externalChannel === null) {
        if (policy.in_account) {
          await this.pool.query('SELECT publish_outbox_event($1, true)', [event.id]);
          report.published += 1;
        } else {
          // Le silence est acceptable ; envoyer au mauvais destinataire, non.
          const verdict = await this.failAttempt(event, 'NOT_NOTIFIABLE');
          report[verdict === 'FAILED' ? 'failed' : 'retried'] += 1;
          report.notNotifiable += 1;
        }
        continue;
      }

      try {
        // HORS transaction (§3.13).
        await this.dispatcher.send({
          address: externalChannel.address,
          channel: externalChannel.channel,
          content: event.event_type,
        });
        await this.pool.query('SELECT publish_outbox_event($1, $2)', [
          event.id,
          policy.in_account,
        ]);
        report.published += 1;
      } catch (err) {
        if (!(err instanceof OutboundFailed)) {
          throw err;
        }
        const verdict = await this.failAttempt(event, 'DISPATCH_FAILED');
        report[verdict === 'FAILED' ? 'failed' : 'retried'] += 1;
      }
    }

    return report;
  }

  private pickChannel(
    policy: Policy,
    address: string | null,
  ): { address: string; channel: OutboundChannel } | null {
    if (address === null || policy.allowed_channels.length === 0) {
      return null;
    }
    const channel = policy.allowed_channels[0];
    return channel === undefined ? null : { address, channel };
  }

  private async policyFor(eventType: string): Promise<Policy> {
    // ::text[] est OBLIGATOIRE : le pilote pg ne sait pas décoder un tableau
    // d'ENUM (proof_channel[]) — il rendrait la chaîne brute « {SMS} », dont
    // le premier élément serait le caractère « { ». Le dispatcher recevrait
    // alors un canal qui n'existe pas. (Défaut réel, attrapé par le test.)
    const result = await this.pool.query<Policy>(
      'SELECT allowed_channels::text[] AS allowed_channels, in_account FROM event_channel_policy WHERE event_type = $1',
      [eventType],
    );
    // Aucune politique = aucun envoi. Le défaut est le silence, jamais l'envoi.
    return result.rows[0] ?? { allowed_channels: [], in_account: false };
  }

  private async resolveAddress(claimId: string | null): Promise<string | null> {
    if (claimId === null) {
      return null;
    }
    // La base REFUSE de résoudre une revendication non ACTIVE : l'événement de
    // reprise de ligne porte justement la revendication révoquée.
    const result = await this.pool.query<{ token: string | null }>(
      'SELECT resolve_notification_address($1) AS token',
      [claimId],
    );
    const token = result.rows[0]?.token ?? null;
    if (token === null) {
      return null;
    }
    try {
      return decrypt(this.crypto.encryption, token);
    } catch {
      return null; // clé absente, jeton altéré : on n'envoie rien.
    }
  }

  private async failAttempt(event: OutboxRow, code: string): Promise<string> {
    const backoff = Math.min(
      this.config.backoffBaseSeconds * 2 ** event.attempts,
      this.config.backoffCapSeconds,
    );
    const result = await this.pool.query<{ fail_outbox_attempt: string }>(
      'SELECT fail_outbox_attempt($1, $2, $3, $4)',
      [event.id, code, this.config.maxAttempts, backoff],
    );
    const verdict = result.rows[0]?.fail_outbox_attempt ?? 'RETRY';
    if (verdict === 'FAILED') {
      // Alerte : un événement est mort. Zéro PII — un type, un identifiant
      // technique, un code.
      console.error(
        `OUTBOX MORTE : event=${event.event_type} id=${event.id} code=${code} — plus aucune tentative`,
      );
    }
    return verdict;
  }
}
