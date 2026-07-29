import { randomBytes } from 'crypto';

/**
 * Un env de trousseaux COMPLET — les quatre familles, valeurs CSPRNG toutes
 * distinctes. Depuis D2, aucun trousseau ne s'assemble sans que les quatre
 * aient été parsés et le contrôle des six paires joué : un env partiel
 * refuse. Les overrides REMPLACENT la famille générée (mêmes noms de
 * variables) — une suite qui a besoin d'une clé précise la fournit.
 */
export function fullKeyringEnv(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const key = (): string => randomBytes(32).toString('base64');
  return {
    USER_CORE_ENC_KEYS: JSON.stringify({ E1: key() }),
    USER_CORE_ENC_ACTIVE_KEY_ID: 'E1',
    USER_CORE_HMAC_KEYS: JSON.stringify({ H1: key() }),
    USER_CORE_HMAC_ACTIVE_KEY_ID: 'H1',
    USER_CORE_PROOF_CODE_KEYS: JSON.stringify({ C1: key() }),
    USER_CORE_PROOF_CODE_ACTIVE_KEY_ID: 'C1',
    USER_CORE_REF_HMAC_KEYS: JSON.stringify({ R1: key() }),
    USER_CORE_REF_HMAC_ACTIVE_KEY_ID: 'R1',
    ...overrides,
  };
}
