/**
 * OutboundDispatcher — LA couture réversible n°3 (CLAUDE.md §3.9, CDC §2.5).
 *
 * « Ce contenu, cette adresse, ce canal. » Rien d'autre. Cette interface ne
 * connaît AUCUNE identité et ne dépend de PERSONNE — c'est ce qui garantit
 * l'absence de cycle entre les cœurs :
 *
 *     Dispatcher ← Verification ← User-Core
 *     Dispatcher ← Plume        ← User-Core          zéro cycle.
 *
 * Si l'envoi vivait dans un module qui a besoin de User-Core, et que
 * User-Core devait envoyer un message : cycle, et plus rien ne démarre seul.
 *
 * ⚠️ CE QUI N'ENTRE PAS ICI, ET QUI N'Y ENTRERA JAMAIS :
 *   - aucun identifiant de titulaire, aucun numéro, aucune revendication,
 *     aucune connexion — la résolution de l'adresse est faite EN AMONT, par
 *     celui qui a le droit de la faire ;
 *   - aucun canal « interne » (une notification dans l'application est écrite
 *     par User-Core dans sa propre table : elle n'a pas d'adresse externe, et
 *     la faire transiter ici obligerait ce fichier à connaître un titulaire —
 *     donc à créer le cycle qu'on vient d'interdire) ;
 *   - aucun coût, aucun tarif : ils sont journalisés par l'appelant.
 *
 * Une 7ᵉ garde CI vérifie mécaniquement, à chaque commit, que ce répertoire
 * ne mentionne aucune notion d'identité. Le zéro-cycle cesse d'être une
 * intention : il devient une propriété vérifiée.
 */

/** Les canaux EXTERNES. La messagerie instantanée viendra ici le jour où le
 *  socle l'admettra comme canal de JOIGNABILITÉ — jamais comme preuve. */
export type OutboundChannel = 'SMS' | 'CALL';

export interface OutboundMessage {
  /** L'adresse déjà résolue : un numéro E.164, opaque pour ce module. */
  address: string;
  channel: OutboundChannel;
  /** Le contenu à faire parvenir (déjà rendu). */
  content: string;
}

export interface OutboundReceipt {
  /** La référence de corrélation du fournisseur. */
  providerRef: string;
}

export class OutboundFailed extends Error {
  constructor(reason: string) {
    // Jamais l'adresse, jamais le contenu — seulement la raison.
    super(`envoi impossible : ${reason}`);
    this.name = 'OutboundFailed';
  }
}

export interface OutboundDispatcher {
  send(message: OutboundMessage): Promise<OutboundReceipt>;
}

export const OUTBOUND_DISPATCHER = 'OUTBOUND_DISPATCHER';
