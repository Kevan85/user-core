import { ConfigViolations } from '../bootstrap/assembly';

/**
 * Configuration des OPÉRATIONS métier /v1 (étape 3) — patron K2 : incomplète
 * ou hors bornes = refus de démarrer. Tout est PARAMÈTRE (§3.11) : les
 * plafonds et la fenêtre se pilotent sans toucher au code.
 */
export interface ProgramOperationsConfig {
  /**
   * LA FENÊTRE UNIQUE (021) : le TTL d'une invitation à ayants droit borne À
   * LA FOIS le rattachement par un détenteur recyclé de la ligne ET
   * l'exposition du nom de l'ayant droit. COURT à dessein — 72 h par défaut :
   * le temps qu'un responsable réagisse (le clic a lieu au guichet, le compte
   * se crée le soir), jamais des semaines d'exposition. Le programme peut
   * ré-inviter : l'idempotence de 012 rend le geste sans coût.
   */
  dependentInvitationTtlSeconds: number;
  /** Plafond d'invitations par CLIENT (toutes lignes) — refus franc, 429. */
  inviteClientCap: number;
  inviteClientCapWindowSeconds: number;
  /** Plafond par LIGNE (tous programmes) — silencieux (suppressed, 012). */
  inviteLineCap: number;
  inviteLineCapWindowSeconds: number;
}

function readInt(
  env: NodeJS.ProcessEnv,
  name: string,
  fallback: number,
  violations: string[],
): number {
  const raw = env[name];
  if (raw === undefined || raw === '') {
    return fallback;
  }
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    violations.push(`${name} invalide : « ${raw} » (entier strictement positif attendu)`);
    return fallback;
  }
  return value;
}

export function assembleProgramOperationsFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): ProgramOperationsConfig {
  const violations: string[] = [];

  const config: ProgramOperationsConfig = {
    dependentInvitationTtlSeconds: readInt(
      env,
      'DEPENDENT_INVITATION_TTL_SECONDS',
      259_200,
      violations,
    ),
    inviteClientCap: readInt(env, 'INVITE_CLIENT_CAP', 5_000, violations),
    inviteClientCapWindowSeconds: readInt(
      env,
      'INVITE_CLIENT_CAP_WINDOW_SECONDS',
      86_400,
      violations,
    ),
    inviteLineCap: readInt(env, 'INVITE_LINE_CAP', 5, violations),
    inviteLineCapWindowSeconds: readInt(
      env,
      'INVITE_LINE_CAP_WINDOW_SECONDS',
      604_800,
      violations,
    ),
  };

  if (violations.length > 0) {
    throw new ConfigViolations(violations);
  }
  return config;
}
