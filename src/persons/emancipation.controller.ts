import { Controller, HttpException, HttpStatus, Post } from '@nestjs/common';

/**
 * L'ÉMANCIPATION — PORTE FERMÉE (LOT U-sec, étape 2 ; migration 031).
 *
 * Ces deux routes existaient et fonctionnaient. Elles rendent désormais 501,
 * et la raison vit ici plutôt que dans un journal de décisions :
 *
 * open_emancipation reçoit DE L'APPELANT la personne visée ET la coordonnée
 * (020:104-109). La preuve qui suit établit « je détiens la ligne que je viens
 * de déclarer » — jamais « je suis cette personne ». La cible est l'identifiant
 * public, conçu pour être DICTÉ AU GUICHET (014:78) : une désignation, pas une
 * authentification. Le plancher d'identité qui corrige cela demande un défi
 * dont la coordonnée est LUE au registre — et il n'a, aujourd'hui, personne à
 * servir : aucun chemin applicatif ne rend un compte inactif — mesuré au
 * 21/08/2026, « UPDATE accounts » s'écrit à DEUX endroits de db/ (028:286,
 * dont le corps est remplacé par celui de 033, et 033:148, le seul vivant),
 * et les deux sont dans l'effacement. Donc la ré-acquisition n'a aucun
 * bénéficiaire ; rien n'est déployé ; la preuve de ligne est un simulateur.
 * (Rédaction antérieure : « un seul UPDATE accounts dans le dépôt » — faux.
 * Mesuré au 10/09/2026 : 48 occurrences dans le dépôt, CE commentaire compris
 * — un balayage inclut son propre texte, CLAUDE.md §8.4. La conclusion, elle,
 * ne tenait pas sur ce comptage mais sur P0116, qui mure l'effacé.)
 *
 * LE MUR EST EN BASE, PAS ICI : 031 retire au rôle applicatif le droit
 * d'exécuter open_emancipation et complete_emancipation. Ce 501 est la FAÇADE
 * — il rend un refus propre au lieu d'un « permission denied » brut. Si ce
 * fichier disparaissait, la porte resterait fermée ; c'est le sens de §3.1.
 *
 * On ferme la porte, on garde les murs : 017 (P0113, la coupure définitive),
 * l'invariant d'émancipation différé et 019 (le droit appartient à la PERSONNE)
 * sont intacts, et les tests continuent de les prouver sous l'owner. Le jour où
 * un usage réel apparaît, le plancher se construit à ce moment-là, avec la
 * contrainte du foyer partagé connue d'avance (CDC §10 n°15).
 *
 * Le service n'est pas touché : son code, ses murs et ses tests restent en
 * place pour l'étape qui reprendra ce chantier.
 */
@Controller('emancipation')
export class EmancipationController {
  @Post('start')
  start(): never {
    throw closed();
  }

  @Post('complete')
  complete(): never {
    throw closed();
  }
}

function closed(): HttpException {
  // Réponse UNIFORME sur les deux routes, et volontairement muette : un
  // endpoint public ne dit rien de plus fermé qu'un autre.
  return new HttpException(
    "l'émancipation n'est pas ouverte dans cette version",
    HttpStatus.NOT_IMPLEMENTED,
  );
}
