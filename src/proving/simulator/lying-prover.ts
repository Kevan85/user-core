import { randomUUID } from 'crypto';
import {
  DeliveryFailed,
  type DeliveryRequest,
  type DeliveryResult,
  type LineOwnershipProver,
} from '../line-ownership-prover';

/**
 * LE SIMULATEUR QUI MENT (CLAUDE.md §5).
 *
 * Un simulateur qui ne rejoue que le chemin heureux ne prouve RIEN : il
 * valide le code qu'on a écrit en pensant au cas nominal, et laisse passer
 * exactement les défauts qui casseront en production, un soir, chez une
 * famille de Kinshasa. Celui-ci ment de six façons — ce sont les six façons
 * dont un opérateur réel nous mentira.
 *
 * Ce que le simulateur NE PEUT PAS faire, par construction : activer une
 * ligne. Aucun de ses mensonges ne produit une possession prouvée — la preuve
 * est le code renvoyé par l'utilisateur, comparé en base. C'est précisément ce
 * que cette classe existe pour démontrer.
 */
export type Lie =
  | 'HONEST'
  /** Le fournisseur livre un AUTRE code que celui demandé. */
  | 'WRONG_CODE'
  /** Il livre... mais bien après l'expiration (réseau RDC, file d'attente opérateur). */
  | 'SLOW'
  /** Il accuse réception et ne livre JAMAIS rien. Aucun rappel, aucune erreur. */
  | 'SILENT'
  /** Il livre DEUX fois (double push) — le client reçoit deux codes. */
  | 'DOUBLE_DELIVERY'
  /** Il échoue franchement (opérateur injoignable, quota, numéro invalide). */
  | 'PROVIDER_ERROR'
  /** Il rend la MÊME référence qu'un envoi précédent (corrélation cassée). */
  | 'REPLAYED_REF';

export interface DeliveredMessage {
  channel: string;
  phone: string;
  code: string;
  providerRef: string;
}

export class LyingProver implements LineOwnershipProver {
  /** Ce que le « téléphone » a réellement reçu — l'observatoire des tests. */
  readonly delivered: DeliveredMessage[] = [];
  /** Nombre d'appels reçus : prouver une ABSENCE se fait en comptant (§5). */
  deliveries = 0;

  private lie: Lie = 'HONEST';
  private lastRef: string | null = null;

  /** Le prochain appel mentira de cette façon. */
  willLie(lie: Lie): void {
    this.lie = lie;
  }

  async deliver(request: DeliveryRequest): Promise<DeliveryResult> {
    this.deliveries += 1;
    const lie = this.lie;

    if (lie === 'PROVIDER_ERROR') {
      throw new DeliveryFailed('opérateur injoignable');
    }

    const providerRef =
      lie === 'REPLAYED_REF' && this.lastRef !== null ? this.lastRef : `sim-${randomUUID()}`;
    this.lastRef = providerRef;

    if (lie === 'SILENT') {
      // Il accuse réception… et rien n'arrive jamais sur le téléphone.
      // AUCUNE ligne dans `delivered` : c'est le comptage qui le prouvera.
      return { providerRef };
    }

    const code = lie === 'WRONG_CODE' ? this.otherCodeThan(request.code) : request.code;
    const message: DeliveredMessage = {
      channel: request.channel,
      phone: request.phone,
      code,
      providerRef,
    };

    this.delivered.push(message);
    if (lie === 'DOUBLE_DELIVERY') {
      this.delivered.push({ ...message });
    }

    // 'SLOW' : le message part, mais il arrivera trop tard. Le test fait
    // vieillir l'horloge de la base (le TTL est en config, pas en dur ici) —
    // le simulateur n'a pas à dormir pour prouver un dépassement.
    return { providerRef };
  }

  private otherCodeThan(code: string): string {
    const digits = code.split('');
    const first = digits[0] ?? '0';
    digits[0] = first === '9' ? '0' : String(Number(first) + 1);
    return digits.join('');
  }
}
