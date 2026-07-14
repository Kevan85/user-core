import { randomUUID } from 'crypto';
import {
  OutboundFailed,
  type OutboundDispatcher,
  type OutboundMessage,
  type OutboundReceipt,
} from '../outbound-dispatcher';

/**
 * Le dispatcher de simulation : il COMPTE ce qu'on lui demande d'envoyer.
 *
 * C'est son intérêt principal : prouver une ABSENCE d'envoi se fait en
 * comptant les appels, jamais en lisant un résultat (CLAUDE.md §5). Les tests
 * du recyclage s'appuient dessus : « zéro message sur la ligne qui vient
 * d'être reprise » n'est démontrable que comme ça.
 *
 * Il ment aussi, comme tout fournisseur réel : échec franc, lenteur, double
 * livraison.
 */
export type DispatchLie = 'HONEST' | 'PROVIDER_ERROR' | 'DOUBLE_DELIVERY';

export class CountingDispatcher implements OutboundDispatcher {
  readonly sent: OutboundMessage[] = [];
  calls = 0;

  private lie: DispatchLie = 'HONEST';

  willLie(lie: DispatchLie): void {
    this.lie = lie;
  }

  /** Combien de messages sont partis sur cette adresse, tous canaux confondus. */
  countTo(address: string): number {
    return this.sent.filter((message) => message.address === address).length;
  }

  async send(message: OutboundMessage): Promise<OutboundReceipt> {
    this.calls += 1;

    if (this.lie === 'PROVIDER_ERROR') {
      throw new OutboundFailed('opérateur injoignable');
    }

    this.sent.push(message);
    if (this.lie === 'DOUBLE_DELIVERY') {
      this.sent.push({ ...message });
    }
    return { providerRef: `disp-${randomUUID()}` };
  }
}
