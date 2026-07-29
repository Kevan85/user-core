import { ConfigViolations } from '../bootstrap/assembly';

/**
 * LE point d'assemblage des trousseaux — le seul fichier du dépôt qui lit
 * une variable USER_CORE_*_KEYS. Une garde CI (motif H) refuse qu'un
 * cinquième trousseau naisse ailleurs : la parade de la dette ② ne vaut que
 * si elle est mécanique (leçon ① — P4 a été « oubliée » trois lots après sa
 * pose, par son propre auteur).
 *
 * QUATRE trousseaux, QUATRE cycles de vie (CDC §6.1, doctrine 006) :
 *
 * - CHIFFREMENT (AES-256-GCM) : tourner la clé active suffit ; les anciennes
 *   valeurs restent déchiffrables par leur enc_key_id. Rotation = un geste
 *   d'exploitation ordinaire.
 * - EMPREINTE téléphone (HMAC-SHA256) : tourner la clé oblige à déchiffrer
 *   ET re-hacher TOUTE la PII, puis à basculer la référence en base. Ce n'est
 *   JAMAIS un réflexe : aucune fonction de rotation n'est livrée, et la
 *   procédure est une migration signée (LOT 2, étape 3).
 * - CODES de possession (HMAC-SHA256) : un code à 6 chiffres vit dans un
 *   espace de 10⁶ — un condensat non salé se retourne en quelques secondes.
 *   Le compromettre ne compromet ni les numéros ni leur unicité.
 * - RÉFÉRENCES d'idempotence des programmes (HMAC-SHA256) : la valeur arrive
 *   en clair dans le payload /v1 et peut porter de la PII — seule son
 *   empreinte est stockée (021).
 *
 * Un secret ne sert JAMAIS deux usages : au boot, toute paire de clés — de
 * deux trousseaux différents COMME du même trousseau — partageant une valeur
 * est un refus de démarrer. (Deux clés identiques dans un même trousseau
 * feraient d'une rotation un geste qui n'a rien tourné.)
 *
 * Les clés des deux premiers trousseaux sont des types NOMINAUX distincts :
 * passer une clé d'empreinte là où on attend une clé de chiffrement ne
 * compile pas. Même parade pour les deux trousseaux à condensat : leurs
 * formes sont structurellement identiques, seule la marque les sépare.
 * Une confusion de trousseau détruirait silencieusement la PII — on la rend
 * non représentable.
 */
declare const encryptionBrand: unique symbol;
declare const fingerprintBrand: unique symbol;
declare const proofCodeBrand: unique symbol;
declare const referenceBrand: unique symbol;

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

export interface ProofCodeKeyring {
  readonly [proofCodeBrand]: true;
  readonly activeKeyId: string;
  readonly keys: Map<string, Buffer>;
}

export interface ReferenceKeyring {
  readonly [referenceBrand]: true;
  readonly activeKeyId: string;
  readonly keys: Map<string, Buffer>;
}

const ENC_KEY_BYTES = 32; // AES-256
const MIN_HMAC_KEY_BYTES = 32; // HMAC-SHA256 : jamais plus court que le condensat

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

/**
 * Toute paire de clés partageant une VALEUR — entre trousseaux comme au sein
 * d'un même trousseau — est une violation. Les messages ne portent que des
 * identifiants de clé, jamais une valeur.
 */
function collisionViolations(
  families: { keysVar: string; material: Map<string, Buffer> }[],
): string[] {
  const violations: string[] = [];
  const entries: { keysVar: string; keyId: string; material: Buffer }[] = [];
  for (const family of families) {
    for (const [keyId, material] of family.material) {
      entries.push({ keysVar: family.keysVar, keyId, material });
    }
  }
  entries.forEach((first, index) => {
    for (const second of entries.slice(index + 1)) {
      if (!first.material.equals(second.material)) {
        continue;
      }
      if (first.keysVar === second.keysVar) {
        violations.push(
          `les clés « ${first.keyId} » et « ${second.keyId} » de ${first.keysVar} ` +
            'ont la MÊME valeur : une « rotation » vers une valeur déjà en service ne tourne rien',
        );
      } else {
        violations.push(
          `la clé « ${first.keyId} » (${first.keysVar}) et la clé « ${second.keyId} » ` +
            `(${second.keysVar}) ont la MÊME valeur : quatre trousseaux, quatre cycles de vie ` +
            '(CDC §6.1) — un secret ne sert jamais deux usages',
        );
      }
    }
  });
  return violations;
}

const ENC_SPEC: RawKeyring = {
  keysVar: 'USER_CORE_ENC_KEYS',
  activeVar: 'USER_CORE_ENC_ACTIVE_KEY_ID',
  minBytes: ENC_KEY_BYTES,
  exactBytes: ENC_KEY_BYTES,
};
const HMAC_SPEC: RawKeyring = {
  keysVar: 'USER_CORE_HMAC_KEYS',
  activeVar: 'USER_CORE_HMAC_ACTIVE_KEY_ID',
  minBytes: MIN_HMAC_KEY_BYTES,
};
const PROOF_CODE_SPEC: RawKeyring = {
  keysVar: 'USER_CORE_PROOF_CODE_KEYS',
  activeVar: 'USER_CORE_PROOF_CODE_ACTIVE_KEY_ID',
  minBytes: MIN_HMAC_KEY_BYTES,
};
const REF_HMAC_SPEC: RawKeyring = {
  keysVar: 'USER_CORE_REF_HMAC_KEYS',
  activeVar: 'USER_CORE_REF_HMAC_ACTIVE_KEY_ID',
  minBytes: MIN_HMAC_KEY_BYTES,
};

export interface CryptoAssembly {
  encryption: Keyring<EncryptionKey>;
  fingerprint: Keyring<FingerprintKey>;
}

/** L'assemblage complet d'un BOOT : les quatre trousseaux, ou rien. */
export interface KeyringAssembly extends CryptoAssembly {
  proofCode: ProofCodeKeyring;
  reference: ReferenceKeyring;
}

function buildCryptoAssembly(
  enc: { activeKeyId: string; material: Map<string, Buffer> },
  fp: { activeKeyId: string; material: Map<string, Buffer> },
): CryptoAssembly {
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

export function assembleCryptoFromEnv(env: NodeJS.ProcessEnv = process.env): CryptoAssembly {
  const violations: string[] = [];
  const enc = parseKeyring(env, ENC_SPEC, violations);
  const fp = parseKeyring(env, HMAC_SPEC, violations);
  violations.push(
    ...collisionViolations([
      { keysVar: ENC_SPEC.keysVar, material: enc.material },
      { keysVar: HMAC_SPEC.keysVar, material: fp.material },
    ]),
  );
  if (violations.length > 0) {
    throw new ConfigViolations(violations);
  }
  return buildCryptoAssembly(enc, fp);
}

export function assembleProofCodeKeyring(
  env: NodeJS.ProcessEnv = process.env,
): ProofCodeKeyring {
  const violations: string[] = [];
  const parsed = parseKeyring(env, PROOF_CODE_SPEC, violations);
  violations.push(
    ...collisionViolations([{ keysVar: PROOF_CODE_SPEC.keysVar, material: parsed.material }]),
  );
  if (violations.length > 0) {
    throw new ConfigViolations(violations);
  }
  return { activeKeyId: parsed.activeKeyId, keys: parsed.material } as ProofCodeKeyring;
}

export function assembleReferenceKeyring(
  env: NodeJS.ProcessEnv = process.env,
): ReferenceKeyring {
  const violations: string[] = [];
  const parsed = parseKeyring(env, REF_HMAC_SPEC, violations);
  violations.push(
    ...collisionViolations([{ keysVar: REF_HMAC_SPEC.keysVar, material: parsed.material }]),
  );
  if (violations.length > 0) {
    throw new ConfigViolations(violations);
  }
  return { activeKeyId: parsed.activeKeyId, keys: parsed.material } as ReferenceKeyring;
}

/**
 * L'assemblage d'un BOOT (api ET worker) : les quatre trousseaux parsés d'un
 * bloc, toutes les violations listées d'un coup, et la non-collision vérifiée
 * sur TOUTES les paires — dette ② soldée. Un processus qui n'utilise pas un
 * trousseau le valide quand même : la config d'une machine est saine ou ne
 * l'est pas, elle ne l'est jamais « pour le processus qui s'en sert ».
 */
export function assembleKeyringsFromEnv(env: NodeJS.ProcessEnv = process.env): KeyringAssembly {
  const violations: string[] = [];
  const enc = parseKeyring(env, ENC_SPEC, violations);
  const fp = parseKeyring(env, HMAC_SPEC, violations);
  const proofCode = parseKeyring(env, PROOF_CODE_SPEC, violations);
  const reference = parseKeyring(env, REF_HMAC_SPEC, violations);

  violations.push(
    ...collisionViolations([
      { keysVar: ENC_SPEC.keysVar, material: enc.material },
      { keysVar: HMAC_SPEC.keysVar, material: fp.material },
      { keysVar: PROOF_CODE_SPEC.keysVar, material: proofCode.material },
      { keysVar: REF_HMAC_SPEC.keysVar, material: reference.material },
    ]),
  );

  if (violations.length > 0) {
    throw new ConfigViolations(violations);
  }

  return {
    ...buildCryptoAssembly(enc, fp),
    proofCode: { activeKeyId: proofCode.activeKeyId, keys: proofCode.material } as ProofCodeKeyring,
    reference: { activeKeyId: reference.activeKeyId, keys: reference.material } as ReferenceKeyring,
  };
}
