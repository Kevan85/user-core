import { readFileSync } from 'fs';
import { join, resolve } from 'path';
import { ed25519KeyBase64 } from '../helpers/auth';
import { appUrl } from '../helpers/db';
import { fullKeyringEnv } from '../helpers/keyring-env';

/**
 * L'ENVIRONNEMENT CONSTRUIT, JAMAIS HÉRITÉ — extrait du test de démarrage le
 * 03/10/2026 pour que le harnais HTTP (api-harness.ts) le construise par LE MÊME
 * code, jamais par une copie (leçon ⑥ : un patron se copie avec son défaut).
 *
 * Jest charge le .env du poste dans process.env : l'hériter ferait passer un test
 * ici et casser en CI (leçon ⑪). Rien n'en est donc lu ici, hors de ce que la base
 * de test impose (appUrl). L'environnement est fait de :
 * - les réglages du gabarit PUBLIC .env.example — si le code exige un jour une
 *   variable que le gabarit ne porte pas, le test de démarrage rougit, et le
 *   gabarit reste complet ;
 * - des secrets TIRÉS pour l'occasion (les quatre trousseaux, la clé de
 *   signature), jamais ceux d'un poste ;
 * - le rôle BRIDÉ de la base de test, et le mode test.
 */
export const ROOT = resolve(__dirname, '..', '..');

export function publicTemplate(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const line of readFileSync(join(ROOT, '.env.example'), 'utf8').split('\n')) {
    const match = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line.trim());
    if (match?.[1] !== undefined && match[2] !== undefined) {
      env[match[1]] = match[2];
    }
  }
  return env;
}

/** Les overrides passent EN DERNIER : un appelant règle ce qui lui est propre, rien d'autre. */
export function constructedEnv(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    ...publicTemplate(),
    ...fullKeyringEnv(),
    AUTH_SIGNING_KEYS: JSON.stringify({ B1: ed25519KeyBase64() }),
    AUTH_ACTIVE_KEY_ID: 'B1',
    DATABASE_URL: appUrl(),
    NODE_ENV: 'test',
    ...overrides,
  };
}
