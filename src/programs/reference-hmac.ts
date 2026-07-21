import { createHmac } from 'crypto';
import { ConfigViolations } from '../bootstrap/assembly';

/**
 * QUATRIÈME trousseau — les RÉFÉRENCES d'idempotence des programmes (021).
 *
 * La référence arrive EN CLAIR dans le payload /v1 ; le service calcule son
 * empreinte ICI et ne stocke JAMAIS la valeur (elle peut porter de la PII :
 * rien n'empêche un programme d'y mettre un nom). Elle ne doit JAMAIS
 * apparaître dans un log — §3.2 : counts, UUID, verdicts, rien d'autre.
 *
 * Pourquoi un HMAC et pas un SHA-256 nu : une référence devinable (un
 * matricule court, un nom) se retrouve au dictionnaire — le condensat serait
 * la valeur en clair avec un chapeau (même argument que P1, les codes).
 *
 * Trousseau DÉDIÉ, cycle de vie distinct (doctrine 006) : le compromettre ne
 * compromet ni les numéros, ni les codes, ni les blobs. Sa rotation est une
 * procédure exceptionnelle dont la conséquence est déclarée en 021 :
 * l'idempotence ne traverse pas une rotation.
 */
export interface ReferenceKeyring {
  activeKeyId: string;
  keys: Map<string, Buffer>;
}

export function assembleReferenceKeyring(
  env: NodeJS.ProcessEnv = process.env,
): ReferenceKeyring {
  const violations: string[] = [];
  const raw = env.USER_CORE_REF_HMAC_KEYS;
  const activeKeyId = env.USER_CORE_REF_HMAC_ACTIVE_KEY_ID ?? '';
  const keys = new Map<string, Buffer>();

  if (!raw) {
    violations.push('USER_CORE_REF_HMAC_KEYS manquant (voir .env.example)');
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
        `USER_CORE_REF_HMAC_KEYS invalide : ${err instanceof Error ? err.message : 'illisible'}`,
      );
    }
  }
  if (!activeKeyId) {
    violations.push('USER_CORE_REF_HMAC_ACTIVE_KEY_ID manquant');
  } else if (keys.size > 0 && !keys.has(activeKeyId)) {
    violations.push(
      `USER_CORE_REF_HMAC_ACTIVE_KEY_ID = « ${activeKeyId} » absent de USER_CORE_REF_HMAC_KEYS`,
    );
  }

  if (violations.length > 0) {
    throw new ConfigViolations(violations);
  }
  return { activeKeyId, keys };
}

export interface HashedReference {
  keyId: string;
  hmac: string;
}

export function hashReference(keyring: ReferenceKeyring, reference: string): HashedReference {
  const material = keyring.keys.get(keyring.activeKeyId);
  if (material === undefined) {
    throw new Error('trousseau des références : clé active absente (config validée au boot)');
  }
  return {
    keyId: keyring.activeKeyId,
    hmac: createHmac('sha256', material).update(reference, 'utf8').digest('hex'),
  };
}
