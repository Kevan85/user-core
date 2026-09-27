import { compileTrustedProxies, type TrustFunction } from '../../src/client-address/client-address';

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
