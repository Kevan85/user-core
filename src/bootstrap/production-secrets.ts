import { readFileSync } from 'fs';
import { resolve } from 'path';
import { ConfigViolations, productionWallsArmed } from './assembly';

/**
 * LE MUR ANTI-SECRETS-PUBLICS (LOT prod, étape 3 — arbitrage C8).
 *
 * .env.example est VERSIONNÉ : toute valeur qui y figure est publique par
 * construction. En production, s'en servir comme secret est un refus de boot.
 * Pas de liste noire de valeurs ni de suffixes (« *_dev_only » est périmable
 * — la prochaine valeur de dev ne portera pas le suffixe) : le fichier publié
 * EST la liste, et elle se maintient toute seule.
 *
 * Deux raffinements, prouvés sur le fichier réel avant d'être gravés :
 * - l'égalité stricte seule raterait un mot de passe réutilisé dans une URL
 *   remaniée (hôte changé, mot de passe gardé) → les identifiants des URL
 *   sont extraits et cherchés en SOUS-CHAÎNE du fichier publié ;
 * - l'égalité sur TOUTES les variables refuserait des réglages légitimes
 *   (PORT=3000, un identifiant de clé « R1 » — publics mais PAS secrets) →
 *   l'égalité ne s'applique qu'aux noms à signature de secret, avec un
 *   plancher de longueur. La signature est STRUCTURELLE (le nom), jamais une
 *   liste de valeurs.
 *
 * Fail-closed (leçon ⑥) : en production, un .env.example illisible n'est pas
 * « rien à vérifier », c'est un refus — sans le fichier, le mur ne peut pas
 * rendre son verdict.
 */
const SECRET_NAME_SIGNATURE = /PASSWORD|SECRET|KEY|TOKEN|DSN/;
const MIN_SECRET_VALUE_LENGTH = 12;
const MIN_URL_PASSWORD_LENGTH = 8;

export function readEnvExample(): string | null {
  try {
    return readFileSync(resolve(process.cwd(), '.env.example'), 'utf8');
  } catch {
    return null;
  }
}

export function assertProductionSecretsNotPublic(
  env: NodeJS.ProcessEnv = process.env,
  readExample: () => string | null = readEnvExample,
): void {
  // F1 : le mode permissif se DÉCLARE (development, test) — absent, vide ou
  // mal orthographié, les murs s'arment. Prédicat unique (F1bis).
  if (!productionWallsArmed(env)) {
    return;
  }

  const example = readExample();
  if (example === null) {
    throw new ConfigViolations([
      '.env.example introuvable : en production, le mur anti-secrets-publics ne peut pas rendre ' +
        'son verdict — le fichier est versionné avec le service et doit être déployé avec lui',
    ]);
  }

  const published = new Map<string, string>();
  for (const line of example.split('\n')) {
    const match = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line.trim());
    const name = match?.[1];
    const value = match?.[2];
    if (name !== undefined && value !== undefined) {
      published.set(name, value);
    }
  }

  const violations: string[] = [];
  for (const [name, value] of Object.entries(env)) {
    if (typeof value !== 'string' || value === '') {
      continue;
    }

    const publishedValue = published.get(name);
    if (
      publishedValue !== undefined &&
      publishedValue.length >= MIN_SECRET_VALUE_LENGTH &&
      SECRET_NAME_SIGNATURE.test(name) &&
      value === publishedValue
    ) {
      // Jamais la valeur dans le message — le nom suffit.
      violations.push(
        `${name} porte la valeur publiée dans .env.example : un secret versionné est public par construction`,
      );
    }

    const credentials = /:\/\/[^/@\s]*:([^@/\s]+)@/.exec(value);
    const password = credentials?.[1];
    if (
      password !== undefined &&
      password.length >= MIN_URL_PASSWORD_LENGTH &&
      example.includes(password)
    ) {
      violations.push(
        `${name} : le mot de passe de l'URL apparaît dans .env.example — il est public par construction`,
      );
    }
  }

  if (violations.length > 0) {
    throw new ConfigViolations(violations);
  }
}
