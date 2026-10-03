import type { DynamicModule } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import type { NextFunction, Request, Response } from 'express';

/**
 * L'APPLICATION HTTP DE L'API — JSON SEULEMENT (lot déploiement, étape 3bis,
 * décision de l'Auditeur du 03/10/2026).
 *
 * Aucun point d'entrée ne lit de formulaire : le contrat n'en prévoit aucun et
 * aucun test n'en envoie. Le lecteur de formulaires de NestJS (urlencoded,
 * étendu) était pourtant actif sur TOUTES les routes, et c'est lui qui chargeait
 * qs. Le retirer sort qs de tout chemin de requête : Express 5.2.1 lit les
 * adresses en mode « simple » (express/lib/application.js:97), et NestJS n'y
 * touche pas. Le lecteur JSON reste, avec sa limite par défaut.
 *
 * LE REFUS DOIT ÊTRE PROPRE — mesuré le 03/10/2026 sur le vrai main.ts.
 * body-parser 2 laisse req.body à undefined quand aucun lecteur ne s'applique, et
 * les contrôleurs le déréférencent. Retirer le seul lecteur de formulaires aurait
 * fait passer une connexion par formulaire de 401 à 500 ; et AVANT ce lot déjà,
 * un corps text/plain ou une requête sans corps rendaient 500. Chaque 500 est une
 * exception « inattendue » qui part vers l'observabilité : un client non
 * authentifié pouvait en fabriquer à volonté. D'où deux règles, au bord, pour
 * toutes les routes :
 * - un corps que le lecteur JSON n'a pas pris : 415, sans qu'un champ soit lu ;
 * - aucun corps : {} — chaque contrôleur rend alors son propre refus, jamais une
 *   exception.
 *
 * Le jour où un fournisseur rappellera le service en formulaire, un lecteur
 * s'ouvrira pour SA seule route — jamais de nouveau pour toutes.
 */
export async function createApiApplication(module: DynamicModule): Promise<NestExpressApplication> {
  const app = await NestFactory.create<NestExpressApplication>(module, { bodyParser: false });
  app.useBodyParser('json');
  app.use(refuseNonJsonBodies);
  return app;
}

/**
 * « La requête porte un corps NON VIDE » : un Transfer-Encoding, ou un
 * Content-Length strictement positif (RFC 9112 §6.3).
 * ⚠️ Divergence VOULUE avec la définition de type-is (hasBody), qui compte une longueur
 * 0 comme un corps : un corps vide ne peut pas être « non JSON », et le refuser
 * casserait les NEUF routes d'écriture sans corps (logout, revoke-all,
 * activate/deactivate, accept/decline…) appelées par un client qui envoie
 * Content-Length: 0 sans Content-Type — ce que font un navigateur et le client
 * HTTP de Node. Mesuré le 03/10/2026 : la première version, alignée sur type-is,
 * répondait 415 à une requête sans corps.
 */
export function carriesBody(req: Request): boolean {
  const length = Number(req.headers['content-length']);
  return req.headers['transfer-encoding'] !== undefined || (Number.isFinite(length) && length > 0);
}

export function refuseNonJsonBodies(req: Request, res: Response, next: NextFunction): void {
  if (req.body !== undefined) {
    next();
    return;
  }
  if (carriesBody(req)) {
    res.status(415).json({ statusCode: 415, message: 'application/json seulement', error: 'Unsupported Media Type' });
    return;
  }
  req.body = {};
  next();
}
