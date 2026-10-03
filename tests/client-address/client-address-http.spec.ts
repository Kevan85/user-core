import { generateKeyPairSync, randomBytes, randomUUID, sign as ed25519Sign } from 'crypto';
import { Pool } from 'pg';
import type { ClientAddressSignal } from '../../src/client-address/client-address';
import { ASSERTION_AUDIENCE } from '../../src/programs/program-auth.service';
import { HARNESS_BUDGET, post, startApi, type RunningApi } from '../bootstrap/api-harness';
import { adminUrl, truncateTables } from '../helpers/db';

/**
 * LES QUATRE SITES, À TRAVERS HTTP (lot déploiement, étape 2, sous-étape 4).
 *
 * client-address.spec.ts prouve la RÉSOLUTION ; ce fichier prouve ce qu'elle
 * PROTÈGE. Les plafonds par adresse de l'inscription, de la connexion, du
 * rafraîchissement et du jeton de programme comptent par CLIENT derrière un
 * aiguilleur déclaré — et jamais selon ce qu'un client écrit dans un en-tête
 * quand la source n'est pas déclarée. Le tout à travers l'application de
 * production (api-harness.ts), dont un premier test vérifie qu'elle l'est bien.
 *
 * Chaque requête est VALIDE et atteint le compteur, consommé avant tout verdict
 * métier sur les quatre sites. Connexion, rafraîchissement et jeton comptent AUSSI
 * par cible (identifiant, jeton présenté, client annoncé) : chaque requête en vise
 * une NEUVE, pour que seule l'adresse puisse trancher — sans quoi un test
 * rougirait, ou passerait, pour une autre raison.
 *
 * Les adresses des clients viennent des plages réservées à la documentation
 * (RFC 5737) : elles ne désignent personne.
 */
interface Site {
  readonly name: string;
  readonly path: string;
  /** Le statut d'une requête qui PASSE le compteur : le verdict métier de cette requête valide. */
  readonly passes: number;
  /** Ce que le point unique doit signaler d'une requête locale sans en-tête, sous murs armés. */
  readonly signals: readonly ClientAddressSignal[];
  /** Un corps valide, à cible NEUVE. */
  body(): object;
}

const programKey = generateKeyPairSync('ed25519').privateKey;

/** Une assertion bien formée et signée, d'un client que personne n'a enregistré : refusée APRÈS le compteur. */
function assertion(): string {
  const encode = (value: object): string => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
  const signingInput = `${encode({ alg: 'EdDSA', typ: 'JWT', kid: 'K1' })}.${encode({
    iss: `client-${randomUUID()}`,
    jti: randomUUID(),
    exp: Math.floor(Date.now() / 1000) + 60,
    aud: ASSERTION_AUDIENCE,
  })}`;
  const signature = ed25519Sign(null, Buffer.from(signingInput, 'utf8'), programKey);
  return `${signingInput}.${signature.toString('base64url')}`;
}

const SECRET = 'harnais-secret-valide';
const PUBLIC_SURFACE: readonly ClientAddressSignal[] = ['DECLARED_PROXY_WITHOUT_CLIENT'];

const SITES: readonly Site[] = [
  { name: 'inscription', path: '/auth/register', passes: 201, signals: PUBLIC_SURFACE, body: () => ({ secret: SECRET }) },
  {
    name: 'connexion',
    path: '/auth/login',
    passes: 401,
    signals: PUBLIC_SURFACE,
    body: () => ({ identifier: randomUUID(), secret: SECRET }),
  },
  {
    name: 'rafraîchissement',
    path: '/auth/refresh',
    passes: 401,
    signals: PUBLIC_SURFACE,
    body: () => ({ refreshToken: randomBytes(32).toString('base64url') }),
  },
  // Surface PROGRAMME : un programme du même serveur appelle légitimement sans en-tête.
  { name: 'jeton de programme', path: '/v1/token', passes: 401, signals: [], body: () => ({ assertion: assertion() }) },
];

const CASES = SITES.map((site, index): [string, Site, number] => [site.name, site, index]);

/** Une rafale : `count` requêtes valides, chacune sous l'en-tête X-Forwarded-For que `forwarded(i)` donne. */
async function burst(
  api: RunningApi,
  site: Site,
  count: number,
  forwarded: (i: number) => string | undefined,
): Promise<number[]> {
  const statuses: number[] = [];
  for (let i = 0; i < count; i += 1) {
    const header = forwarded(i);
    const headers: Record<string, string> = header === undefined ? {} : { 'x-forwarded-for': header };
    statuses.push(await post(api.port, site.path, { body: site.body(), headers }));
  }
  return statuses;
}

/** Le budget entier qui passe, puis le premier refus. */
function exhausted(site: Site): number[] {
  return [...Array<number>(HARNESS_BUDGET).fill(site.passes), 429];
}

beforeAll(async () => {
  // L'inscription crée de vrais comptes : on part d'une base propre, sous owner.
  const owner = new Pool({ connectionString: adminUrl() });
  try {
    await truncateTables(owner, 'session_refresh_tokens', 'sessions', 'account_secrets', 'accounts', 'persons');
  } finally {
    await owner.end();
  }
});

describe('le harnais EST l’application de production', () => {
  test('un formulaire reçoit 415 : le harnais passe par createApiApplication, comme main.ts', async () => {
    // Sans ce test, un harnais construit un jour avec NestFactory.create
    // directement passerait tous les tests de budget sans que personne le voie.
    const api = await startApi();
    try {
      const form = { body: 'identifier=inconnu&secret=x', headers: { 'content-type': 'application/x-www-form-urlencoded' } };
      expect(await post(api.port, '/auth/login', form)).toBe(415);
    } finally {
      await api.close();
    }
  });
});

describe('aiguilleur DÉCLARÉ (la boucle locale) : un budget PAR CLIENT', () => {
  let api: RunningApi;

  beforeAll(async () => {
    api = await startApi({ env: { USER_CORE_TRUSTED_PROXIES: '127.0.0.1' } });
  });

  afterAll(async () => {
    await api.close();
  });

  test.each(CASES)('%s : deux clients, deux budgets — A refusé au dépassement pendant que B passe encore', async (_name, site, index) => {
    const clientA = `203.0.113.${10 + index}`;
    const clientB = `198.51.100.${10 + index}`;
    expect(await burst(api, site, HARNESS_BUDGET + 1, () => clientA)).toEqual(exhausted(site));
    expect(await burst(api, site, 1, () => clientB)).toEqual([site.passes]);
  });
});

describe('source NON déclarée : un en-tête forgé ne vaut rien', () => {
  let api: RunningApi;

  beforeAll(async () => {
    api = await startApi({ env: { USER_CORE_TRUSTED_PROXIES: 'NONE' } });
  });

  afterAll(async () => {
    await api.close();
  });

  test.each(CASES)('%s : des X-Forwarded-For forgés, tous différents, ne font qu’UN budget — celui de la socket', async (_name, site) => {
    expect(await burst(api, site, HARNESS_BUDGET + 1, (i) => `192.0.2.${i + 1}`)).toEqual(exhausted(site));
    // Le budget épuisé est bien celui de la socket : sans en-tête, elle est refusée aussi.
    expect(await burst(api, site, 1, () => undefined)).toEqual([429]);
  });
});

describe('la SURFACE de chaque site est regardée — murs armés, aiguilleur déclaré', () => {
  // Leçon ⑮ : sans ce test, un contrôleur public passé en PROGRAM par erreur
  // éteindrait ses signaux sans faire rougir un seul test. Une application neuve
  // par site : chaque signal n'est émis qu'une fois par point unique.
  test.each(CASES)('%s : des requêtes locales SANS en-tête', async (_name, site) => {
    const raised: ClientAddressSignal[] = [];
    const api = await startApi({
      env: { NODE_ENV: 'production', USER_CORE_TRUSTED_PROXIES: '127.0.0.1' },
      signal: (signal) => raised.push(signal),
    });
    try {
      // Le 429 prouve que les requêtes ont TRAVERSÉ le point unique : le compteur qui
      // refuse est clé par son résultat. Un statut seul ne le prouverait pas — sur
      // /v1/token, le refus d'avant (assertion absente) est aussi un 401 — et
      // « aucun signal » ne vaudrait rien sur une requête arrêtée avant lui.
      expect(await burst(api, site, HARNESS_BUDGET + 1, () => undefined)).toEqual(exhausted(site));
      expect(raised).toEqual(site.signals);
    } finally {
      await api.close();
    }
  });
});
