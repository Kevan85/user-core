import type { IncomingMessage } from 'http';
import {
  ClientAddress,
  clientAddressSignalName,
  compileTrustedProxies,
  reportClientAddressSignal,
  type ClientAddressSignal,
  type TrustFunction,
} from '../../src/client-address/client-address';
import * as observability from '../../src/observability/sentry';

/**
 * Le point unique de l'adresse cliente — étape 1 : ce qui fait d'une liste
 * d'aiguilleurs une fonction de confiance. Chaque refus ci-dessous est un cas
 * MESURÉ le 27/09/2026 sur la référence elle-même, pas une hypothèse.
 */
function trustOf(entries: string[]): TrustFunction {
  const result = compileTrustedProxies(entries);
  if (!result.ok) {
    throw new Error(`refusée : ${result.violations.join(' | ')}`);
  }
  return result.trust;
}

function violationsOf(entries: string[]): string {
  const result = compileTrustedProxies(entries);
  return result.ok ? '(acceptée)' : result.violations.join(' | ');
}

describe('la notation canonique est un mur', () => {
  test.each([
    ['1', "l'habitude Express « trust proxy = 1 » — la référence y lit 0.0.0.1"],
    ['0x7f.0.0.1', 'notation hexadécimale — la référence l’accepte'],
    ['127.1', 'notation abrégée'],
    ['true', 'un booléen Express'],
    ['*', 'un joker'],
    ['localhost', "un nom d'hôte"],
    ['10/8', 'adresse abrégée'],
    ['10.0.0.0/08', 'préfixe à zéro de tête — la référence l’accepte'],
    ['10.0.0.0/255.0.0.0', 'forme masque — la référence l’accepte'],
    ['10.0.0.0/33', 'préfixe hors bornes'],
    ['::1/129', 'préfixe hors bornes'],
    ['0.0.0.0/0', 'tout IPv4'],
    ['::/0', 'tout IPv6'],
  ])('« %s » est refusé (%s), et le refus NOMME l’entrée', (entry) => {
    expect(violationsOf([entry])).toContain(entry);
  });

  test.each([['127.0.0.1'], ['::1'], ['10.0.0.0/8'], ['fc00::/7'], ['::ffff:127.0.0.1']])(
    '« %s » est accepté',
    (entry) => {
      expect(compileTrustedProxies([entry]).ok).toBe(true);
    },
  );

  test('toutes les violations sont rendues d’un bloc', () => {
    const violations = violationsOf(['1', 'true', '127.0.0.1']);
    expect(violations).toContain('« 1 »');
    expect(violations).toContain('« true »');
    expect(violations).not.toContain('« 127.0.0.1 »');
  });
});

describe('le contrôle de largeur — un DÉTECTEUR DE FUMÉE', () => {
  test.each([
    [['::ffff:0:0/96']],
    [['0.0.0.0/1', '128.0.0.0/1']],
    [['128.0.0.0/1']],
    [['::/1', '8000::/1']],
  ])('%j fait confiance à une moitié d’Internet ⇒ refusée « trop large »', (entries) => {
    expect(violationsOf(entries)).toContain('trop large');
  });

  test.each([
    [['127.0.0.1', '::1']],
    [['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7']],
    [['203.0.113.0/24']],
  ])('%j est une configuration légitime ⇒ acceptée', (entries) => {
    expect(compileTrustedProxies(entries).ok).toBe(true);
  });

  test('CE QU’IL NE VOIT PAS : une plage publique étroite mais fausse passe', () => {
    // 198.51.100.0/24 n'est l'aiguilleur de personne ici — et le détecteur
    // l'accepte, parce qu'il ne sait pas quelles adresses sont les nôtres. La
    // seule preuve reste la vérification après déploiement : deux sources, deux
    // budgets. Ce test existe pour que personne ne lise « largeur contrôlée »
    // comme « liste juste ».
    expect(compileTrustedProxies(['198.51.100.0/24']).ok).toBe(true);
  });
});

describe('ce que la liste compilée croit — les cas mesurés', () => {
  test('une liste vide ne fait confiance à personne : la socket fait foi', () => {
    const trust = trustOf([]);
    expect(trust('127.0.0.1', 0)).toBe(false);
    expect(trust('::1', 0)).toBe(false);
  });

  test('un aiguilleur déclaré 127.0.0.1 est reconnu sous sa forme double pile ::ffff:127.0.0.1', () => {
    // Le défaut du patron payment-core (comparaison de chaînes exactes), mesuré
    // le 27/09/2026 : listen(port) sans hôte écoute sur ::, et un client IPv4 y
    // arrive en ::ffff:127.0.0.1. Ici, il est reconnu.
    const trust = trustOf(['127.0.0.1']);
    expect(trust('::ffff:127.0.0.1', 0)).toBe(true);
    expect(trust('203.0.113.7', 0)).toBe(false);
  });

  test('CVE-2026-90711 — une déclaration IPv6 ne fait confiance à AUCUNE adresse IPv4 (2.0.7 rougit ici)', () => {
    // Mesuré le 27/09/2026 : proxy-addr 2.0.7 faisait confiance à 203.0.113.7 et
    // à 8.8.8.8 depuis ::/64 ; la 2.0.8 non. Sur 2.0.7, cette liste serait même
    // refusée « trop large » par le détecteur — et trustOf rougirait. Un retour à
    // la version vulnérable ne passe donc pas en silence.
    const trust = trustOf(['::/64']);
    for (const candidate of ['203.0.113.7', '8.8.8.8', '::ffff:8.8.8.8']) {
      expect(trust(candidate, 0)).toBe(false);
    }
  });
});

// --- Étape 2 : la résolution et ses deux signaux -----------------------------

const A3: ClientAddressSignal = 'DECLARED_PROXY_WITHOUT_CLIENT';
const A3BIS: ClientAddressSignal = 'FORWARDED_FROM_UNDECLARED_LOCAL_SOURCE';

/** Une requête telle que la voit la référence : l'adresse de la socket et l'en-tête. */
function request(socket: string | undefined, forwardedFor?: string): IncomingMessage {
  const headers = forwardedFor === undefined ? {} : { 'x-forwarded-for': forwardedFor };
  return { socket: { remoteAddress: socket }, connection: { remoteAddress: socket }, headers } as unknown as IncomingMessage;
}

function resolver(declared: string[], armed = true): { address: ClientAddress; signals: ClientAddressSignal[] } {
  const signals: ClientAddressSignal[] = [];
  const address = new ClientAddress({ trust: trustOf(declared), armed, signal: (s) => signals.push(s) });
  return { address, signals };
}

describe('la résolution — une requête devient une adresse cliente', () => {
  test('aucun aiguilleur : un X-Forwarded-For forgé est ignoré, la socket fait foi', () => {
    expect(resolver([]).address.of(request('203.0.113.9', '1.2.3.4'), 'PUBLIC')).toBe('203.0.113.9');
  });

  test('aiguilleur déclaré : l’adresse qu’il a vue, même reçu sous la forme double pile', () => {
    expect(resolver(['127.0.0.1']).address.of(request('::ffff:127.0.0.1', '203.0.113.7'), 'PUBLIC')).toBe('203.0.113.7');
  });

  test('une entrée forgée à GAUCHE ne passe pas : seule compte celle que l’aiguilleur a écrite', () => {
    expect(resolver(['127.0.0.1']).address.of(request('::ffff:127.0.0.1', '1.2.3.4, 203.0.113.7'), 'PUBLIC')).toBe(
      '203.0.113.7',
    );
  });

  test('deux sauts de confiance : le client derrière les deux', () => {
    const { address } = resolver(['127.0.0.1', '10.0.0.0/8']);
    expect(address.of(request('127.0.0.1', '203.0.113.7, 10.0.0.5'), 'PUBLIC')).toBe('203.0.113.7');
  });

  test('jamais une clé que le client fabrique : une entrée non-IP retombe sur la socket', () => {
    expect(resolver(['127.0.0.1']).address.of(request('::ffff:127.0.0.1', 'pas-une-ip'), 'PUBLIC')).toBe('127.0.0.1');
  });

  test('un client, une clé : ::ffff:a.b.c.d est normalisée', () => {
    expect(resolver([]).address.of(request('::ffff:198.51.100.4'), 'PUBLIC')).toBe('198.51.100.4');
  });

  test('socket déjà détruite : « unknown », exactement comme avant ce lot', () => {
    expect(resolver([]).address.of(request(undefined), 'PUBLIC')).toBe('unknown');
  });
});

describe('A3 — un aiguilleur DÉCLARÉ qui ne transmet aucune adresse cliente', () => {
  test('site public, murs armés : un signal — un seul par processus — et aucun refus', () => {
    const { address, signals } = resolver(['127.0.0.1']);
    expect(address.of(request('::ffff:127.0.0.1'), 'PUBLIC')).toBe('127.0.0.1');
    expect(address.of(request('::ffff:127.0.0.1'), 'PUBLIC')).toBe('127.0.0.1');
    expect(signals).toEqual([A3]);
  });

  test('CONTRÔLE NÉGATIF — site PROGRAMME : un programme du même serveur arrive légitimement sans en-tête', () => {
    const { address, signals } = resolver(['127.0.0.1']);
    address.of(request('::ffff:127.0.0.1'), 'PROGRAM');
    expect(signals).toEqual([]);
  });

  test('CONTRÔLE NÉGATIF — murs relâchés : aucun signal', () => {
    const { address, signals } = resolver(['127.0.0.1'], false);
    address.of(request('::ffff:127.0.0.1'), 'PUBLIC');
    expect(signals).toEqual([]);
  });

  test('CONTRÔLE NÉGATIF — un aiguilleur qui transmet le client : aucun signal', () => {
    const { address, signals } = resolver(['127.0.0.1']);
    address.of(request('::ffff:127.0.0.1', '203.0.113.7'), 'PUBLIC');
    expect(signals).toEqual([]);
  });
});

describe('A3bis — un X-Forwarded-For venu d’une source locale ou privée NON déclarée', () => {
  test('le cas du conteneur : 127.0.0.1 déclaré, la requête arrive de la passerelle 172.18.0.1 avec un en-tête', () => {
    // L'aiguilleur de l'hôte joint un port publié ; le conteneur le voit arriver
    // depuis la passerelle de son réseau, pas depuis 127.0.0.1. L'en-tête est
    // ignoré (la source n'est pas déclarée) : sans ce signal, le plafond global
    // reviendrait en silence. Aucun refus : la requête est servie.
    const { address, signals } = resolver(['127.0.0.1']);
    expect(address.of(request('172.18.0.1', '203.0.113.7'), 'PUBLIC')).toBe('172.18.0.1');
    expect(signals).toEqual([A3BIS]);
  });

  test('la boucle locale non déclarée compte aussi', () => {
    const { address, signals } = resolver(['10.0.0.1']);
    address.of(request('::1', '203.0.113.7'), 'PUBLIC');
    expect(signals).toEqual([A3BIS]);
  });

  test('CONTRÔLE NÉGATIF — la même requête venue d’une adresse DÉCLARÉE ne lève rien', () => {
    const { address, signals } = resolver(['172.18.0.1']);
    expect(address.of(request('172.18.0.1', '203.0.113.7'), 'PUBLIC')).toBe('203.0.113.7');
    expect(signals).toEqual([]);
  });

  test('CONTRÔLE NÉGATIF — venue d’une adresse PUBLIQUE non déclarée : ignorée, pas signalée', () => {
    const { address, signals } = resolver(['127.0.0.1']);
    expect(address.of(request('203.0.113.9', '1.2.3.4'), 'PUBLIC')).toBe('203.0.113.9');
    expect(signals).toEqual([]);
  });

  test('CONTRÔLE NÉGATIF — une source locale SANS en-tête (une sonde de santé) : rien', () => {
    const { address, signals } = resolver(['10.0.0.1']);
    address.of(request('127.0.0.1'), 'PUBLIC');
    expect(signals).toEqual([]);
  });

  test('CONTRÔLE NÉGATIF — site programme, ou murs relâchés : rien', () => {
    const programme = resolver(['127.0.0.1']);
    programme.address.of(request('172.18.0.1', '203.0.113.7'), 'PROGRAM');
    const relache = resolver(['127.0.0.1'], false);
    relache.address.of(request('172.18.0.1', '203.0.113.7'), 'PUBLIC');
    expect([...programme.signals, ...relache.signals]).toEqual([]);
  });

  test('un signal par processus ET par signature : deux signatures, deux signaux, jamais plus', () => {
    const { address, signals } = resolver(['127.0.0.1']);
    for (let i = 0; i < 3; i += 1) {
      address.of(request('::ffff:127.0.0.1'), 'PUBLIC');
      address.of(request('172.18.0.1', '203.0.113.7'), 'PUBLIC');
    }
    expect(signals).toEqual([A3, A3BIS]);
  });
});

describe('le puits de production — le signal SURVIT au filtre d’observabilité (leçon ⑨)', () => {
  test.each([[A3], [A3BIS]])('%s : le vrai scrubEvent relaie le NOM au lieu de le réduire à « Error »', (signal) => {
    const name = clientAddressSignalName(signal);
    const event = { type: undefined, exception: { values: [{ type: name, value: 'message' }] } };
    const scrubbed = observability.scrubEvent(event as Parameters<typeof observability.scrubEvent>[0], undefined);
    expect(scrubbed.exception?.values?.[0]?.type).toBe(name);
  });

  test('reportClientAddressSignal : une erreur nommée part, un avertissement sans adresse', () => {
    const captured: unknown[] = [];
    const warned: string[] = [];
    const capture = jest.spyOn(observability, 'captureError').mockImplementation((err) => void captured.push(err));
    const warn = jest.spyOn(console, 'warn').mockImplementation((...args: unknown[]) => void warned.push(args.join(' ')));
    try {
      reportClientAddressSignal(A3BIS);
    } finally {
      capture.mockRestore();
      warn.mockRestore();
    }
    expect(captured).toHaveLength(1);
    expect((captured[0] as Error).name).toBe(clientAddressSignalName(A3BIS));
    expect(warned).toHaveLength(1);
    expect(warned[0]).toContain(A3BIS);
    expect(warned[0]).not.toMatch(/[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+/);
  });
});
