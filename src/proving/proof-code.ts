import { createHmac, randomInt, timingSafeEqual } from 'crypto';
import { ConfigViolations } from '../bootstrap/assembly';

/**
 * Le code de possession : généré par le cœur (CSPRNG), livré par le
 * fournisseur, et conservé UNIQUEMENT sous forme de HMAC (P1).
 *
 * Pourquoi un HMAC à clé dédiée, et pas un SHA-256 : un code à 6 chiffres vit
 * dans un espace de 10⁶. Un condensat non salé se retourne par force brute en
 * quelques secondes — le « hash » serait le code lui-même, en clair, avec un
 * chapeau. La clé rend le condensat inattaquable sans elle.
 *
 * TROISIÈME trousseau, distinct du chiffrement (AES) et de l'empreinte
 * téléphone (HMAC) : trois usages, trois cycles de vie. Le compromettre ne
 * compromet ni les numéros ni leur unicité.
 */
export interface ProofCodeKeyring {
  activeKeyId: string;
  keys: Map<string, Buffer>;
}

export function assembleProofCodeKeyring(
  env: NodeJS.ProcessEnv = process.env,
): ProofCodeKeyring {
  const violations: string[] = [];
  const raw = env.USER_CORE_PROOF_CODE_KEYS;
  const activeKeyId = env.USER_CORE_PROOF_CODE_ACTIVE_KEY_ID ?? '';
  const keys = new Map<string, Buffer>();

  if (!raw) {
    violations.push('USER_CORE_PROOF_CODE_KEYS manquant (voir .env.example)');
  } else {
    try {
      const parsed: unknown = JSON.parse(raw);
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('objet JSON { key_id: base64 } attendu');
      }
      for (const [keyId, value] of Object.entries(parsed)) {
        if (typeof value !== 'string') {
          throw new Error(`clé « ${keyId} » : chaîne base64 attendue`);
        }
        const bytes = Buffer.from(value, 'base64');
        if (bytes.length < 32) {
          throw new Error(`clé « ${keyId} » : 32 octets minimum, ${bytes.length} reçus`);
        }
        keys.set(keyId, bytes);
      }
    } catch (err) {
      violations.push(
        `USER_CORE_PROOF_CODE_KEYS invalide : ${err instanceof Error ? err.message : 'illisible'}`,
      );
    }
  }
  if (!activeKeyId) {
    violations.push('USER_CORE_PROOF_CODE_ACTIVE_KEY_ID manquant');
  } else if (keys.size > 0 && !keys.has(activeKeyId)) {
    violations.push(
      `USER_CORE_PROOF_CODE_ACTIVE_KEY_ID = « ${activeKeyId} » absent de USER_CORE_PROOF_CODE_KEYS`,
    );
  }

  if (violations.length > 0) {
    throw new ConfigViolations(violations);
  }
  return { activeKeyId, keys };
}

/**
 * Le code lui-même : CSPRNG, longueur en CONFIG (jamais figée — un opérateur
 * ou un régulateur peut l'imposer différente ; CDC §9 : on paramètre).
 */
export function generateProofCode(digits: number): string {
  if (!Number.isInteger(digits) || digits < 4 || digits > 10) {
    throw new Error(`longueur de code invalide : ${digits}`);
  }
  let code = '';
  for (let i = 0; i < digits; i++) {
    code += String(randomInt(0, 10));
  }
  return code;
}

export interface HashedCode {
  keyId: string;
  hmac: string;
}

export function hashProofCode(keyring: ProofCodeKeyring, code: string): HashedCode {
  const material = keyring.keys.get(keyring.activeKeyId);
  if (material === undefined) {
    throw new Error('trousseau des codes : clé active absente (config validée au boot)');
  }
  return {
    keyId: keyring.activeKeyId,
    hmac: createHmac('sha256', material).update(code, 'utf8').digest('hex'),
  };
}

/** Recalcule sous une clé NOMMÉE — le code présenté se compare à la ligne écrite. */
export function hashProofCodeUnder(
  keyring: ProofCodeKeyring,
  keyId: string,
  code: string,
): string | null {
  const material = keyring.keys.get(keyId);
  if (material === undefined) {
    return null;
  }
  return createHmac('sha256', material).update(code, 'utf8').digest('hex');
}

export function codeHashEquals(a: string, b: string): boolean {
  const bufferA = Buffer.from(a, 'utf8');
  const bufferB = Buffer.from(b, 'utf8');
  return bufferA.length === bufferB.length && timingSafeEqual(bufferA, bufferB);
}
