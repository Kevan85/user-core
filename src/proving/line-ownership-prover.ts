/**
 * LineOwnershipProver — LA couture réversible n°2 (CLAUDE.md §3.9).
 *
 * Derrière : un simulateur aujourd'hui ; demain un flash call, un SMS, ou la
 * Silent Network Authentication SI les opérateurs RDC y participent (inconnue
 * de terrain, CDC §9 — à obtenir, jamais à présumer). Le cœur ne connaît
 * JAMAIS un fournisseur d'OTP : il connaît ce vocabulaire, et rien d'autre.
 *
 * DOCTRINE GRAVÉE DANS LE TYPE (CDC §6.2) : le canal est 'SMS' ou 'CALL'.
 * Seul un canal qui transite par la SIM prouve la possession de la LIGNE —
 * et c'est la SIM qui sera débitée par le paiement. WhatsApp est un canal de
 * JOIGNABILITÉ, jamais de PREUVE : il n'entre pas dans ce type, et il n'entre
 * pas dans l'ENUM de la base.
 *
 * ⚠️ CE QUE CETTE INTERFACE N'EXPOSE PAS, À DESSEIN :
 *   - aucun champ « verdict » ni « verified » : un fournisseur ne décide
 *     JAMAIS qu'une possession est prouvée. La preuve, c'est le code que
 *     l'utilisateur renvoie, comparé EN BASE (verify_possession_code). Un
 *     fournisseur compromis ou bogué ne peut donc pas activer une ligne ;
 *   - aucun code en clair en retour : le code est généré par le cœur, remis
 *     au fournisseur pour livraison, et n'existe ensuite que sous forme de
 *     HMAC en base.
 */
export type ProofChannel = 'SMS' | 'CALL';

export interface DeliveryRequest {
  channel: ProofChannel;
  /** Le numéro déchiffré — TRANSIENT : transmis, puis oublié. Jamais persisté, jamais loggé. */
  phone: string;
  /** Le code à faire parvenir. Le cœur ne le garde que haché. */
  code: string;
}

export interface DeliveryResult {
  /** Référence de corrélation du fournisseur — tracée sur la preuve. */
  providerRef: string;
}

export class DeliveryFailed extends Error {
  constructor(reason: string) {
    // Jamais le numéro, jamais le code — seulement la raison.
    super(`livraison impossible : ${reason}`);
    this.name = 'DeliveryFailed';
  }
}

export interface LineOwnershipProver {
  /**
   * Demande la livraison d'un code par un canal qui transite par la SIM.
   * Lève DeliveryFailed si le fournisseur n'a pas pu livrer (muet, erreur,
   * délai dépassé) — l'appelant clôt alors la preuve, sans jamais l'activer.
   */
  deliver(request: DeliveryRequest): Promise<DeliveryResult>;
}

export const LINE_OWNERSHIP_PROVER = 'LINE_OWNERSHIP_PROVER';
