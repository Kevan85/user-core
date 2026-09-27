import { compileTrustedProxies, type TrustFunction } from '../client-address/client-address';
import { ConfigViolations, productionWallsArmed } from './assembly';

/**
 * LE MUR DE L'AIGUILLEUR (lot déploiement, étape 1).
 *
 * Derrière un aiguilleur, seul l'en-tête X-Forwarded-For qu'IL écrit dit qui est
 * le client — et cet en-tête ne se croit que s'il arrive d'une adresse DÉCLARÉE.
 * Ce fichier lit la déclaration ; la notation, la compilation et la largeur
 * vivent au point unique (src/client-address/client-address.ts).
 *
 * AUCUN DES DEUX DÉFAUTS N'EST SÛR — le défaut est donc le REFUS (leçon ⑩).
 * Trop peu de confiance (un aiguilleur réel, non déclaré) : tous les clients
 * partagent son adresse, et chaque plafond « par adresse » devient un plafond
 * global — un levier de déni de service. Trop de confiance : n'importe quel
 * client écrit l'adresse de son choix, et le plafond ne borne plus rien. Un
 * oubli ne doit choisir ni l'un ni l'autre en silence : sous murs de
 * production, une variable absente ou vide REFUSE le démarrage.
 *
 * « AUCUN AIGUILLEUR » S'ÉCRIT NONE, JAMAIS VIDE (arbitrage Auditeur,
 * 27/09/2026) : dans un fichier d'environnement, une valeur oubliée et une liste
 * vide voulue s'écrivent pareil. NONE est un acte, le vide n'en est pas un. NONE
 * mêlé à des adresses est une contradiction, refusée ; « none » n'est pas NONE.
 *
 * Murs relâchés (development, test) : l'absence vaut NONE, en silence — le poste
 * de développement ne change pas. Une valeur DÉCLARÉE, elle, est validée dans
 * tous les modes : une faute de frappe se dit tout de suite.
 */
export const TRUSTED_PROXIES_VARIABLE = 'USER_CORE_TRUSTED_PROXIES';
export const NO_TRUSTED_PROXY = 'NONE';

export interface TrustedProxies {
  /** Les aiguilleurs déclarés ; vide = aucun, la socket fait foi. */
  readonly declared: readonly string[];
  readonly trust: TrustFunction;
}

function compiled(entries: readonly string[]): TrustedProxies {
  const result = compileTrustedProxies(entries);
  if (!result.ok) {
    throw new ConfigViolations(result.violations.map((violation) => `${TRUSTED_PROXIES_VARIABLE} : ${violation}`));
  }
  return { declared: entries, trust: result.trust };
}

export function assembleTrustedProxiesFromEnv(env: NodeJS.ProcessEnv = process.env): TrustedProxies {
  const entries = (env[TRUSTED_PROXIES_VARIABLE] ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry !== '');

  if (entries.length === 0) {
    if (productionWallsArmed(env)) {
      throw new ConfigViolations([
        `${TRUSTED_PROXIES_VARIABLE} absente ou vide sous murs de production : déclarer ` +
          `${NO_TRUSTED_PROXY} (service exposé sans aiguilleur) ou la liste des adresses des aiguilleurs. ` +
          `Trop peu de confiance ferait de chaque plafond par adresse un plafond global ; trop, un ` +
          `plafond que n'importe quel client contourne`,
      ]);
    }
    return compiled([]);
  }
  if (!entries.includes(NO_TRUSTED_PROXY)) {
    return compiled(entries);
  }
  if (entries.some((entry) => entry !== NO_TRUSTED_PROXY)) {
    throw new ConfigViolations([
      `${TRUSTED_PROXIES_VARIABLE} : ${NO_TRUSTED_PROXY} mêlé à des adresses — contradiction, rien n'est déclaré`,
    ]);
  }
  return compiled([]);
}
