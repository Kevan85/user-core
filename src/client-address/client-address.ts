import { isIP } from 'net';
import proxyaddr from 'proxy-addr';

/**
 * LE POINT UNIQUE DE L'ADRESSE CLIENTE (lot déploiement — la compilation de la
 * liste des aiguilleurs à l'étape 1, la résolution d'une requête à l'étape 2).
 *
 * POURQUOI UN POINT UNIQUE. Derrière un aiguilleur (le relais HTTPS placé devant
 * le service), l'adresse de la socket est la SIENNE, pour tous les clients : les
 * plafonds « par adresse » de l'inscription, de la connexion, du rafraîchissement
 * et du jeton de programme deviennent des plafonds GLOBAUX — le levier de déni de
 * service que login-throttle.ts interdit en toutes lettres. Tout usage de la
 * référence vit ici, et le motif J (étape 5 de ce lot) refusera hors de ce
 * fichier toute forme de code qui lit l'adresse. Le cinquième site existe déjà en
 * germe : emancipation.service.ts exige une adresse cliente, et seul le 501 de
 * 031 l'empêche de la recevoir.
 *
 * LA RÉFÉRENCE, PAS UNE COPIE. Le calcul est confié à proxy-addr — la
 * bibliothèque qu'Express utilise lui-même. Le patron voisin (payment-core,
 * client-ip.ts) a été lu à la source et n'est PAS recopié : mesuré le 27/09/2026,
 * il compare des chaînes exactes (un aiguilleur déclaré 127.0.0.1 arrive en
 * ::ffff:127.0.0.1 sur une écoute double pile, et n'est jamais reconnu), il ne
 * lit qu'un saut, et une liste vide y passe en silence.
 * Version épinglée 2.0.8 : mesuré le 27/09/2026, la 2.0.7 faisait confiance à des
 * adresses IPv4 publiques quelconques depuis une déclaration purement IPv6
 * (::/64) — le correctif que son HISTORY.md annonce (CVE-2026-90711). Un test le
 * regarde (tests/client-address/client-address.spec.ts) : un retour à 2.0.7 rougit.
 *
 * LA NOTATION CANONIQUE EST UN MUR, PAS UN STYLE. La référence accepte « 1 »
 * comme l'adresse 0.0.0.1 : quiconque est habitué à Express (« trust proxy = 1 »,
 * un saut) croirait avoir déclaré son aiguilleur et n'aurait rien déclaré — le
 * plafond global reviendrait en silence. N'entre que la notation que net.isIP()
 * reconnaît, avec une longueur de préfixe écrite sans zéro de tête. La forme
 * « masque » (10.0.0.0/255.0.0.0) est refusée aussi.
 *
 * LE CONTRÔLE DE LARGEUR EST UN DÉTECTEUR DE FUMÉE, PAS UNE PREUVE. Il demande à
 * la liste compilée si elle ferait confiance à l'un de six résolveurs DNS
 * publics, répartis sur les quatre quarts de l'espace IPv4 et sur IPv6 : aucun
 * n'est l'aiguilleur de qui que ce soit. Il attrape les listes qui font
 * confiance à une moitié d'Internet (::ffff:0:0/96, 0.0.0.0/1 + 128.0.0.0/1 —
 * deux formes que la référence accepte). ⚠️ Il n'attrape PAS une plage publique
 * étroite mais fausse : un /24 qui n'est pas le nôtre passe. La seule preuve que
 * la liste est la bonne reste la vérification après déploiement — deux sources,
 * deux budgets.
 */
export type TrustFunction = (address: string, hop: number) => boolean;

export type CompiledTrust =
  | { readonly ok: true; readonly trust: TrustFunction }
  | { readonly ok: false; readonly violations: readonly string[] };

/** Aucun n'est l'aiguilleur de personne : s'ils sont de confiance, la liste est trop large. */
const WIDTH_CANARIES: readonly string[] = [
  '8.8.8.8',
  '77.88.8.8',
  '149.112.112.112',
  '208.67.222.222',
  '2001:4860:4860::8888',
  '2606:4700:4700::1111',
];

// Une longueur de préfixe canonique : un entier sans zéro de tête — donc jamais /0.
const CANONICAL_PREFIX = /^[1-9][0-9]{0,2}$/;

function canonicalViolation(entry: string): string | null {
  const slash = entry.indexOf('/');
  const family = isIP(slash === -1 ? entry : entry.slice(0, slash));
  if (family === 0) {
    return `« ${entry} » n'est pas une adresse IP en notation canonique (ni « 1 », ni « 127.1 », ni un nom d'hôte)`;
  }
  if (slash === -1) {
    return null;
  }
  const prefix = entry.slice(slash + 1);
  if (!CANONICAL_PREFIX.test(prefix) || Number(prefix) > (family === 4 ? 32 : 128)) {
    return `« ${entry} » : longueur de préfixe non canonique (un entier sans zéro de tête, jamais /0 ni un masque)`;
  }
  return null;
}

/**
 * Le SEUL chemin par lequel une liste d'aiguilleurs devient une fonction de
 * confiance. Toutes les violations sont rendues d'un bloc. Une liste vide ne
 * fait confiance à personne : la socket fait foi.
 */
export function compileTrustedProxies(entries: readonly string[]): CompiledTrust {
  const violations = entries
    .map(canonicalViolation)
    .filter((violation): violation is string => violation !== null);
  if (violations.length > 0) {
    return { ok: false, violations };
  }
  let trust: TrustFunction;
  try {
    trust = proxyaddr.compile([...entries]);
  } catch (err) {
    return { ok: false, violations: [`refusée par la référence : ${err instanceof Error ? err.message : 'erreur inconnue'}`] };
  }
  const trusted = WIDTH_CANARIES.filter((canary) => trust(canary, 0));
  if (trusted.length > 0) {
    return {
      ok: false,
      violations: [
        `liste trop large — elle ferait confiance à ${trusted.join(', ')}, qui ne sont l'aiguilleur de ` +
          `personne : n'importe quel client pourrait écrire l'adresse de son choix et contourner tout ` +
          `plafond par adresse (détecteur de fumée : une plage étroite mais fausse, il ne la voit pas)`,
      ],
    };
  }
  return { ok: true, trust };
}
