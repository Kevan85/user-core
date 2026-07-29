import * as Sentry from '@sentry/node';
import { ConfigViolations, productionWallsArmed } from '../bootstrap/assembly';

/**
 * OBSERVABILITÉ — Sentry, ZÉRO PII (LOT prod, étape 5 — §3.2, le point de
 * vigilance n°1 du lot : une fuite part chez un TIERS et ne se rattrape pas).
 *
 * LA LISTE BLANCHE EST UNE RECONSTRUCTION : l'événement expédié est REBÂTI
 * champ par champ — rien n'entre par défaut. Ce qui sort, et RIEN d'autre :
 * identifiant d'événement, horodatage, niveau, environnement, nom de
 * l'erreur (assaini), SQLSTATE s'il en porte un, et les cadres de pile
 * (fichier, fonction, ligne — du code, jamais des données). Le MESSAGE d'une
 * erreur n'est JAMAIS expédié : nos RAISE EXCEPTION Postgres interpolent des
 * valeurs (un hmac_key_id en 006:133), et un message applicatif peut porter
 * n'importe quoi.
 *
 * LES BREADCRUMBS SONT MORTS, à TROIS étages (le piège signalé au cadrage :
 * actifs par défaut, ils voyagent avec l'événement — console, requêtes HTTP,
 * SQL selon les intégrations) :
 *   1. defaultIntegrations: false — aucune intégration n'en fabrique ;
 *   2. maxBreadcrumbs: 0 + beforeBreadcrumb → null — un ajout MANUEL meurt ;
 *   3. la reconstruction ne copie pas la clé — ce qui aurait survécu n'entre
 *      pas dans l'événement.
 * L'espion de tests/observability le PROUVE sur l'enveloppe réellement
 * expédiée — il ne le suppose pas.
 *
 * DSN : obligatoire quand les murs de production sont armés (C2 — un
 * déploiement sans DSN partirait aveugle et personne ne l'apprendrait : on
 * ne reçoit pas d'alerte pour dire qu'on ne recevra pas d'alertes). Le mode
 * permissif déclaré (F1) boote sans DSN : l'observabilité est simplement
 * coupée en dev.
 */
export interface ObservabilityConfig {
  dsn: string | null;
  environment: string;
}

export function assembleObservabilityFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): ObservabilityConfig {
  const armed = productionWallsArmed(env);
  const dsn = env.SENTRY_DSN ?? null;
  if (armed && dsn === null) {
    throw new ConfigViolations([
      'SENTRY_DSN manquant : murs de production armés, partir aveugle en silence est un ' +
        'fail-open (C2) — le DSN est obligatoire (voir .env.example)',
    ]);
  }
  return { dsn, environment: armed ? 'production' : 'development' };
}

// Le NOM d'une erreur est un identifiant de classe — s'il ne ressemble pas à
// un identifiant, on ne le relaie pas (ceinture : rien d'arbitraire ne sort).
const SAFE_ERROR_NAME = /^[\w$ ]{1,64}$/;
// SQLSTATE : cinq caractères alphanumériques (P0109, 23505, 42501…).
const SQLSTATE = /^[0-9A-Z]{5}$/;

function safeName(type: string | undefined): string {
  return type !== undefined && SAFE_ERROR_NAME.test(type) ? type : 'Error';
}

function sqlstateOf(err: unknown): string | null {
  if (typeof err === 'object' && err !== null && 'code' in err) {
    const { code } = err as { code?: unknown };
    if (typeof code === 'string' && SQLSTATE.test(code)) {
      return code;
    }
  }
  return null;
}

export function scrubEvent(
  event: Sentry.ErrorEvent,
  hint: Sentry.EventHint | undefined,
): Sentry.ErrorEvent {
  const code = sqlstateOf(hint?.originalException);
  const values = (event.exception?.values ?? []).map((entry) => ({
    type: safeName(entry.type),
    // JAMAIS le message : un code stable s'il existe, sinon un marqueur.
    value: code !== null ? `SQLSTATE ${code}` : '[message retiré — zéro PII (§3.2)]',
    stacktrace:
      entry.stacktrace?.frames === undefined
        ? undefined
        : {
            frames: entry.stacktrace.frames.map((frame) => ({
              filename: frame.filename,
              function: frame.function,
              lineno: frame.lineno,
              colno: frame.colno,
            })),
          },
  }));

  // RECONSTRUCTION : l'objet rendu ne contient QUE ces clés — contexts,
  // request, user, tags, extra, modules, breadcrumbs n'existent pas ici.
  // (`type` est le discriminant du SDK pour « événement d'erreur » — une
  // étiquette de forme, pas une donnée.)
  return {
    type: undefined,
    event_id: event.event_id,
    timestamp: event.timestamp,
    platform: event.platform,
    level: event.level,
    environment: event.environment,
    exception: { values },
  };
}

/**
 * Rend true si l'observabilité est ARMÉE — et la vérité se demande AU SDK
 * après init(), jamais à la présence du DSN (G1) : un DSN mal formé fait que
 * le SDK désactive son transport SANS lever — le service partirait aveugle
 * en croyant être surveillé, le fail-open exact que C2 ferme. On ne recopie
 * pas la validation interne du SDK (deux définitions divergeraient — F1bis) :
 * on l'interroge, comme assertFingerprintKeyAligned interroge la base.
 * Murs de production armés + transport absent = refus de boot.
 */
export function initObservability(
  config: ObservabilityConfig,
  transport?: Sentry.NodeOptions['transport'],
): boolean {
  if (config.dsn === null) {
    return false;
  }
  Sentry.init({
    dsn: config.dsn,
    environment: config.environment,
    defaultIntegrations: false,
    integrations: [],
    maxBreadcrumbs: 0,
    beforeBreadcrumb: () => null,
    sendDefaultPii: false,
    // Les traces/métriques n'existent pas ici : des erreurs, rien d'autre.
    tracesSampleRate: 0,
    beforeSend: (event, hint) => scrubEvent(event, hint),
    transport,
  });

  const client = Sentry.getClient();
  const armed = client !== undefined && client.getTransport() !== undefined;
  if (!armed && config.environment === 'production') {
    throw new ConfigViolations([
      'SENTRY_DSN présent mais le transport ne s\'est PAS armé (DSN illisible pour le SDK ?) — ' +
        'partir aveugle en croyant être surveillé est le fail-open exact que C2 ferme (G1)',
    ]);
  }
  return armed;
}

export function captureError(err: unknown): void {
  Sentry.captureException(err);
}

export async function flushObservability(): Promise<void> {
  await Sentry.flush(2000);
}
