import { isIP } from 'net';
import { ConfigViolations, productionWallsArmed } from './assembly';

/**
 * LE MUR DE L'ÉCOUTE (lot déploiement, étape 7 — bloc A-2026-10-03-2).
 *
 * L'adresse sur laquelle le service écoute. Hors conteneur, derrière un aiguilleur
 * de la même machine : la boucle locale, et le port du service n'est joignable que
 * par lui. Dans un conteneur : toutes les interfaces DU CONTENEUR, la restriction
 * étant la publication du port sur la boucle locale de l'hôte. La valeur de chaque
 * mode d'exécution est écrite dans docs/ops/DEPLOIEMENT.md.
 *
 * UN NOM QUI N'APPARTIENT QU'À USER-CORE. Un nom générique (HOST) arrive hérité du
 * shell ou de la plateforme sans que personne l'ait déclaré, et satisferait ce mur
 * en silence (leçon ⑩). USER_CORE_LISTEN_HOST ne s'hérite de personne.
 *
 * Sous murs de production, la variable se DÉCLARE ou le démarrage est refusé :
 * écouter partout par oubli exposerait le port du service à côté de l'aiguilleur.
 * Toute valeur déclarée est validée dans tous les modes, et seul un littéral IP
 * passe : « localhost » est un NOM, que chaque machine résout à sa façon (127.0.0.1
 * ou ::1). Murs relâchés, variable absente : l'écoute d'avant ce lot, toutes les
 * interfaces, inchangée.
 */
export const LISTEN_HOST_VARIABLE = 'USER_CORE_LISTEN_HOST';

export interface ListenHost {
  /** L'adresse d'écoute déclarée ; undefined = toutes les interfaces (murs relâchés seulement). */
  readonly host: string | undefined;
}

export function assembleListenHostFromEnv(env: NodeJS.ProcessEnv = process.env): ListenHost {
  const declared = (env[LISTEN_HOST_VARIABLE] ?? '').trim();
  if (declared === '') {
    if (productionWallsArmed(env)) {
      throw new ConfigViolations([
        `${LISTEN_HOST_VARIABLE} absente ou vide sous murs de production : déclarer l'adresse d'écoute ` +
          `(la boucle locale hors conteneur, toutes les interfaces dans un conteneur dont le port n'est ` +
          `publié que sur la boucle locale de l'hôte — docs/ops/DEPLOIEMENT.md). Écouter partout par ` +
          `oubli exposerait le port du service à côté de l'aiguilleur`,
      ]);
    }
    return { host: undefined };
  }
  if (isIP(declared) === 0) {
    throw new ConfigViolations([
      `${LISTEN_HOST_VARIABLE} : « ${declared} » n'est pas une adresse IP littérale ` +
        `(ni un nom comme « localhost », ni une liste, ni un port)`,
    ]);
  }
  return { host: declared };
}
