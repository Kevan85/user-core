import type { IncomingMessage } from 'http';
import { isIP } from 'net';
import proxyaddr from 'proxy-addr';
import { captureError } from '../observability/sentry';

/**
 * LE POINT UNIQUE DE L'ADRESSE CLIENTE (lot déploiement — la compilation de la
 * liste des aiguilleurs à l'étape 1, la résolution d'une requête à l'étape 2).
 *
 * POURQUOI UN POINT UNIQUE. Derrière un aiguilleur (le relais HTTPS placé devant
 * le service), l'adresse de la socket est la SIENNE, pour tous les clients : les
 * plafonds « par adresse » de l'inscription, de la connexion, du rafraîchissement
 * et du jeton de programme deviennent des plafonds GLOBAUX — le levier de déni de
 * service que login-throttle.ts interdit en toutes lettres. Tout usage de la
 * référence vit ici, et le motif J (tools/check-guards.sh et son job CI) refuse
 * hors de ce fichier toute forme de code qui lit l'adresse — hors d'ici, une
 * adresse cliente s'appelle clientIp. Le cinquième site existe déjà en
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

export const CLIENT_ADDRESS = 'CLIENT_ADDRESS';

/** Qui appelle : le PUBLIC (inscription, connexion, rafraîchissement) ou un PROGRAMME (/v1/token). */
export type Surface = 'PUBLIC' | 'PROGRAM';

/**
 * Les deux signatures d'un aiguilleur mal déclaré. Un signal par processus et par
 * signature, aucune donnée personnelle, aucun refus de requête.
 * - A3 : un aiguilleur DÉCLARÉ n'a transmis aucune adresse cliente — chaque
 *   plafond par adresse redevient global, sans bruit.
 * - A3bis : un X-Forwarded-For arrive d'une source NON déclarée qui est locale ou
 *   privée — la signature d'un aiguilleur vu sous une autre adresse que celle
 *   déclarée (la passerelle d'un réseau de conteneurs, typiquement), donc ignoré.
 */
export type ClientAddressSignal = 'DECLARED_PROXY_WITHOUT_CLIENT' | 'FORWARDED_FROM_UNDECLARED_LOCAL_SOURCE';

export interface ClientAddressOptions {
  readonly trust: TrustFunction;
  /** productionWallsArmed(), dérivé UNE fois à l'assemblage (F1bis) — jamais re-déduit ici. */
  readonly armed: boolean;
  readonly signal: (signal: ClientAddressSignal) => void;
}

// La boucle locale, le lien local et les plages privées, au sens de la référence —
// jamais d'une liste recopiée. Aucun client d'Internet n'arrive d'une de ces
// adresses : c'est ce qui rend A3bis presque muet sur le sain.
const LOCAL_OR_PRIVATE: TrustFunction = proxyaddr.compile(['loopback', 'linklocal', 'uniquelocal']);

// ::ffff:a.b.c.d — une adresse IPv4 vue par une écoute double pile : un client, une clé.
const IPV4_MAPPED = /^::ffff:([0-9]{1,3}(?:[.][0-9]{1,3}){3})$/i;

function normalized(address: string): string {
  return IPV4_MAPPED.exec(address)?.[1] ?? address;
}

/**
 * LA RÉSOLUTION — le seul endroit où une requête devient une adresse cliente.
 *
 * La SURFACE est un paramètre OBLIGATOIRE (condition c de l'Auditeur) : le site
 * /v1/token ne peut pas lever un signal public par oubli. Un programme hébergé sur
 * le même serveur qui appelle directement le port arrive légitimement d'une adresse
 * de confiance, sans en-tête : sur ce site, A3 crierait sur le sain — et un
 * détecteur qui crie sur le sain finit assoupli (CLAUDE.md §3.14bis ②).
 * Les deux signaux n'existent que sous murs armés : en développement il n'y a pas
 * d'aiguilleur à mal déclarer.
 */
export class ClientAddress {
  private readonly emitted = new Set<ClientAddressSignal>();

  constructor(private readonly options: ClientAddressOptions) {}

  of(req: IncomingMessage, surface: Surface): string {
    const socket = req.socket.remoteAddress;
    if (socket === undefined) {
      return 'unknown'; // socket déjà détruite : le comportement d'avant ce lot, inchangé
    }
    const resolved = proxyaddr(req, this.options.trust);
    if (surface === 'PUBLIC' && this.options.armed) {
      this.watch(req, socket, resolved);
    }
    // Jamais une clé que le client fabrique : une entrée non-IP retombe sur la socket.
    return normalized(isIP(resolved) === 0 ? socket : resolved);
  }

  private watch(req: IncomingMessage, socket: string, resolved: string): void {
    const { trust } = this.options;
    if (trust(socket, 0) && trust(resolved, 0)) {
      this.emit('DECLARED_PROXY_WITHOUT_CLIENT');
    } else if (!trust(socket, 0) && LOCAL_OR_PRIVATE(socket, 0) && req.headers['x-forwarded-for'] !== undefined) {
      this.emit('FORWARDED_FROM_UNDECLARED_LOCAL_SOURCE');
    }
  }

  private emit(signal: ClientAddressSignal): void {
    if (!this.emitted.has(signal)) {
      this.emitted.add(signal);
      this.options.signal(signal);
    }
  }
}

/**
 * L'observabilité ne relaie d'une erreur que son NOM (sentry.ts, liste blanche ;
 * le message est toujours retiré) : le signal tient donc tout entier dans le nom,
 * en caractères de mot — et un test le fait passer par le vrai filtre.
 */
export function clientAddressSignalName(signal: ClientAddressSignal): string {
  return `ClientAddressSignal_${signal}`;
}

const SIGNAL_EXPLANATIONS: Record<ClientAddressSignal, string> = {
  DECLARED_PROXY_WITHOUT_CLIENT:
    "un aiguilleur déclaré n'a transmis aucune adresse cliente : chaque plafond par adresse redevient global",
  FORWARDED_FROM_UNDECLARED_LOCAL_SOURCE:
    "un X-Forwarded-For arrive d'une source locale ou privée NON déclarée : l'aiguilleur n'est pas vu sous l'adresse déclarée",
};

/** Le puits de production. Aucune adresse, jamais : le nom du signal et son explication. */
export function reportClientAddressSignal(signal: ClientAddressSignal): void {
  const error = new Error(signal);
  error.name = clientAddressSignalName(signal);
  captureError(error);
  console.warn(`[ADRESSE CLIENTE] ${signal} — ${SIGNAL_EXPLANATIONS[signal]} (voir USER_CORE_TRUSTED_PROXIES).`);
}
