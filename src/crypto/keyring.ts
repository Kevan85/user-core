import { ConfigViolations } from '../bootstrap/assembly';

/**
 * Deux trousseaux, deux cycles de vie, et le TYPE l'impose (CDC §6.1).
 *
 * - Trousseau de CHIFFREMENT (AES-256-GCM) : tourner la clé active suffit ;
 *   les anciennes valeurs restent déchiffrables par leur enc_key_id. Rotation
 *   = un geste d'exploitation ordinaire.
 * - Trousseau d'EMPREINTE (HMAC-SHA256) : tourner la clé oblige à déchiffrer
 *   ET re-hacher TOUTE la PII, puis à basculer la référence en base. Ce n'est
 *   JAMAIS un réflexe : aucune fonction de rotation n'est livrée, et la
 *   procédure est une migration signée (LOT 2, étape 3).
 *
 * Les deux clés sont des types NOMINAUX distincts : passer une clé d'empreinte
 * là où on attend une clé de chiffrement ne compile pas. Une confusion de
 * trousseau détruirait silencieusement la PII — on la rend non représentable.
 */
declare const encryptionBrand: unique symbol;
declare const fingerprintBrand: unique symbol;

export interface EncryptionKey {
  readonly [encryptionBrand]: true;
  readonly keyId: string;
  readonly material: Buffer;
}

export interface FingerprintKey {
  readonly [fingerprintBrand]: true;
  readonly keyId: string;
  readonly material: Buffer;
}

export interface Keyring<K> {
  /** La clé qui SIGNE/CHIFFRE aujourd'hui — une seule, toujours. */
  readonly activeKeyId: string;
  /** Toutes les clés connues, y compris les anciennes (lecture). */
  get(keyId: string): K | undefined;
  active(): K;
}

const ENC_KEY_BYTES = 32; // AES-256
const MIN_FINGERPRINT_KEY_BYTES = 32; // HMAC-SHA256 : jamais plus court que le condensat

class MapKeyring<K extends { keyId: string }> implements Keyring<K> {
  constructor(
    readonly activeKeyId: string,
    private readonly keys: Map<string, K>,
  ) {}

  get(keyId: string): K | undefined {
    return this.keys.get(keyId);
  }

  active(): K {
    const key = this.keys.get(this.activeKeyId);
    if (key === undefined) {
      // Impossible après l'assemblage (validé au boot) — filet, pas garde.
      throw new Error('trousseau : la clé active est absente');
    }
    return key;
  }
}

interface RawKeyring {
  keysVar: string;
  activeVar: string;
  minBytes: number;
  exactBytes?: number;
}

function parseKeyring(
  env: NodeJS.ProcessEnv,
  spec: RawKeyring,
  violations: string[],
): { activeKeyId: string; material: Map<string, Buffer> } {
  const raw = env[spec.keysVar];
  const activeKeyId = env[spec.activeVar] ?? '';
  const material = new Map<string, Buffer>();

  if (!raw) {
    violations.push(`${spec.keysVar} manquant (voir .env.example)`);
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
        if (spec.exactBytes !== undefined && bytes.length !== spec.exactBytes) {
          throw new Error(
            `clé « ${keyId} » : ${spec.exactBytes} octets exigés, ${bytes.length} reçus`,
          );
        }
        if (bytes.length < spec.minBytes) {
          throw new Error(
            `clé « ${keyId} » : ${spec.minBytes} octets minimum, ${bytes.length} reçus`,
          );
        }
        material.set(keyId, bytes);
      }
    } catch (err) {
      // Jamais la valeur de la clé dans le message — seulement son identifiant.
      violations.push(
        `${spec.keysVar} invalide : ${err instanceof Error ? err.message : 'illisible'}`,
      );
    }
  }

  if (!activeKeyId) {
    violations.push(`${spec.activeVar} manquant`);
  } else if (material.size > 0 && !material.has(activeKeyId)) {
    violations.push(`${spec.activeVar} = « ${activeKeyId} » absent de ${spec.keysVar}`);
  }

  return { activeKeyId, material };
}

export interface CryptoAssembly {
  encryption: Keyring<EncryptionKey>;
  fingerprint: Keyring<FingerprintKey>;
}

export function assembleCryptoFromEnv(env: NodeJS.ProcessEnv = process.env): CryptoAssembly {
  const violations: string[] = [];

  const enc = parseKeyring(
    env,
    {
      keysVar: 'USER_CORE_ENC_KEYS',
      activeVar: 'USER_CORE_ENC_ACTIVE_KEY_ID',
      minBytes: ENC_KEY_BYTES,
      exactBytes: ENC_KEY_BYTES,
    },
    violations,
  );
  const fp = parseKeyring(
    env,
    {
      keysVar: 'USER_CORE_HMAC_KEYS',
      activeVar: 'USER_CORE_HMAC_ACTIVE_KEY_ID',
      minBytes: MIN_FINGERPRINT_KEY_BYTES,
    },
    violations,
  );

  // Une même valeur servant aux deux usages ruinerait la séparation des
  // cycles de vie : on refuse net, au boot.
  for (const [encId, encMaterial] of enc.material) {
    for (const [fpId, fpMaterial] of fp.material) {
      if (encMaterial.equals(fpMaterial)) {
        violations.push(
          `la clé de chiffrement « ${encId} » et la clé d'empreinte « ${fpId} » ont la MÊME valeur : ` +
            'les deux trousseaux ont des cycles de vie distincts (CDC §6.1) et ne partagent jamais un secret',
        );
      }
    }
  }

  if (violations.length > 0) {
    throw new ConfigViolations(violations);
  }

  const encKeys = new Map<string, EncryptionKey>();
  for (const [keyId, buffer] of enc.material) {
    encKeys.set(keyId, { keyId, material: buffer } as EncryptionKey);
  }
  const fpKeys = new Map<string, FingerprintKey>();
  for (const [keyId, buffer] of fp.material) {
    fpKeys.set(keyId, { keyId, material: buffer } as FingerprintKey);
  }

  return {
    encryption: new MapKeyring(enc.activeKeyId, encKeys),
    fingerprint: new MapKeyring(fp.activeKeyId, fpKeys),
  };
}
