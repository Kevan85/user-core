import * as Sentry from '@sentry/node';
import { ConfigViolations } from '../../src/bootstrap/assembly';
import {
  assembleObservabilityFromEnv,
  initObservability,
} from '../../src/observability/sentry';

/**
 * ÉTAPE 5 — ZÉRO PII vers Sentry, prouvé par ESPION SUR LE TRANSPORT : on
 * capture l'enveloppe RÉELLEMENT expédiée (ce qui partirait sur le réseau),
 * on COMPTE les envois (§5 : pour une absence, compte les appels — jamais un
 * agrégat seul), et on cherche les marqueurs interdits dans les octets qui
 * sortent. Inspecter l'événement en mémoire ne prouverait rien : c'est le
 * transport qui parle au tiers.
 */
const sentEnvelopes: string[] = [];

const spyTransport: Sentry.NodeOptions['transport'] = (options) =>
  Sentry.createTransport(options, (request) => {
    sentEnvelopes.push(
      typeof request.body === 'string' ? request.body : Buffer.from(request.body).toString('utf8'),
    );
    return Promise.resolve({ statusCode: 200 });
  });

const PHONE_MARKER = '+8801700000999';
const NAME_MARKER = 'KABEYA-JUNIOR-MARQUEUR';
const TOKEN_MARKER = 'jeton-secret-MARQUEUR-XYZ';
const BREADCRUMB_MARKER = 'MIETTE-INTERDITE-MARQUEUR';
const DETAIL_MARKER = 'DETAIL-POSTGRES-MARQUEUR';

describe('étape 5 — le scrubbing, prouvé sur le transport', () => {
  beforeAll(() => {
    const active = initObservability(
      { dsn: 'https://clepublique@exemple.ingest.invalide/1', environment: 'test', armed: false },
      spyTransport,
    );
    expect(active).toBe(true);
  });

  beforeEach(() => {
    sentEnvelopes.length = 0;
  });

  afterAll(async () => {
    await Sentry.close(2000);
  });

  test('une erreur dont le message PORTE numéro, nom et jeton : UN envoi, ZÉRO marqueur dedans', async () => {
    Sentry.captureException(
      new Error(`échec pour ${PHONE_MARKER} de ${NAME_MARKER}, jeton=${TOKEN_MARKER}`),
    );
    await Sentry.flush(2000);

    expect(sentEnvelopes).toHaveLength(1); // l'espion COMPTE : un envoi, pas zéro, pas deux
    const body = sentEnvelopes[0] as string;
    expect(body).not.toContain(PHONE_MARKER);
    expect(body).not.toContain(NAME_MARKER);
    expect(body).not.toContain(TOKEN_MARKER);
    // Ce qui sort : le NOM de l'erreur et le marqueur de retrait — §3.2.
    expect(body).toContain('"type":"Error"');
    expect(body).toContain('message retiré');
  });

  test('une erreur Postgres : le SQLSTATE sort, le message interpolé et le detail JAMAIS', async () => {
    const pgError = Object.assign(
      new Error(`empreinte calculée sous la clé « ${TOKEN_MARKER} » — rotation exigée`),
      { code: 'P0109', detail: DETAIL_MARKER, name: 'error' },
    );
    Sentry.captureException(pgError);
    await Sentry.flush(2000);

    expect(sentEnvelopes).toHaveLength(1);
    const body = sentEnvelopes[0] as string;
    expect(body).toContain('SQLSTATE P0109');
    expect(body).not.toContain(TOKEN_MARKER);
    expect(body).not.toContain(DETAIL_MARKER);
  });

  test('LES BREADCRUMBS SONT MORTS : un ajout manuel + un console.error ne voyagent pas avec l\'événement', async () => {
    Sentry.addBreadcrumb({ message: BREADCRUMB_MARKER, category: 'test' });
    console.error(`bruit de console avec ${BREADCRUMB_MARKER}`);
    Sentry.captureException(new Error('déclencheur'));
    await Sentry.flush(2000);

    expect(sentEnvelopes).toHaveLength(1);
    const body = sentEnvelopes[0] as string;
    expect(body).not.toContain(BREADCRUMB_MARKER);
    expect(body).not.toContain('"breadcrumbs"');
  });

  test('la reconstruction ne laisse passer AUCUN enrichissement : user, tags, extra, contexts, request', async () => {
    Sentry.withScope((scope) => {
      scope.setUser({ id: 'compte-123', username: NAME_MARKER });
      scope.setTag('ligne', PHONE_MARKER);
      scope.setExtra('payload', { phone: PHONE_MARKER });
      scope.setContext('requete', { url: `/v1/personnes/${NAME_MARKER}` });
      Sentry.captureException(new Error('déclencheur'));
    });
    await Sentry.flush(2000);

    expect(sentEnvelopes).toHaveLength(1);
    const body = sentEnvelopes[0] as string;
    expect(body).not.toContain(PHONE_MARKER);
    expect(body).not.toContain(NAME_MARKER);
    expect(body).not.toContain('"user"');
    expect(body).not.toContain('"tags"');
    expect(body).not.toContain('"extra"');
    expect(body).not.toContain('"contexts"');
    expect(body).not.toContain('"request"');
  });

  test('un nom d\'erreur difforme est assaini — rien d\'arbitraire ne sort par le champ type', async () => {
    const weird = new Error('déclencheur');
    weird.name = `Nom<script>${PHONE_MARKER}</script>`;
    Sentry.captureException(weird);
    await Sentry.flush(2000);

    expect(sentEnvelopes).toHaveLength(1);
    const body = sentEnvelopes[0] as string;
    expect(body).not.toContain(PHONE_MARKER);
    expect(body).toContain('"type":"Error"');
  });
});

describe('étape 5 — C2 : le DSN est obligatoire quand les murs sont armés (via productionWallsArmed)', () => {
  test('murs armés (production, absent, faute de frappe) sans DSN → refus de boot', () => {
    expect(() => assembleObservabilityFromEnv({ NODE_ENV: 'production' })).toThrow(
      ConfigViolations,
    );
    expect(() => assembleObservabilityFromEnv({})).toThrow(/SENTRY_DSN manquant/);
    expect(() => assembleObservabilityFromEnv({ NODE_ENV: 'produciton' })).toThrow(
      ConfigViolations,
    );
  });

  test('murs armés + DSN → assemblé ; mode permissif sans DSN → coupé, pas refusé', () => {
    const armed = assembleObservabilityFromEnv({
      NODE_ENV: 'production',
      SENTRY_DSN: 'https://cle@exemple.ingest.invalide/1',
    });
    expect(armed.dsn).not.toBeNull();
    expect(armed.environment).toBe('production');
    expect(armed.armed).toBe(true); // LA dérivation unique du prédicat (F1bis)

    const relaxed = assembleObservabilityFromEnv({ NODE_ENV: 'development' });
    expect(relaxed.dsn).toBeNull();
    expect(initObservability(relaxed)).toBe(false); // coupée : aucun client armé
  });
});

describe('étape 6 — G1 : la vérité se demande au SDK, jamais à la présence du DSN', () => {
  test('DSN PRÉSENT mais illisible + murs armés → refus de boot (le transport ne s\'est pas armé)', () => {
    // « cle-invalide » : le tiret est refusé par la validation interne du SDK
    // — qu'on n'a PAS recopiée : on interroge le client après init().
    expect(() =>
      initObservability({ dsn: 'https://cle-invalide@exemple.ingest.invalide/1', environment: 'production', armed: true }),
    ).toThrow(/ne s'est PAS armé/);
  });

  test('DSN illisible en mode permissif → false, pas de refus (le dev voit le console.error du SDK)', () => {
    expect(
      initObservability({ dsn: 'https://cle-invalide@exemple.ingest.invalide/1', environment: 'development', armed: false }),
    ).toBe(false);
  });

  test('DSN lisible → true, et c\'est le SDK qui l\'a dit (client + transport)', () => {
    expect(
      initObservability({ dsn: 'https://clevalide@exemple.ingest.invalide/1', environment: 'production', armed: true }),
    ).toBe(true);
  });
});
