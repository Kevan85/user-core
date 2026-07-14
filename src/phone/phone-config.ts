import { Pool } from 'pg';
import { ConfigViolations } from '../bootstrap/assembly';
import type { CryptoAssembly } from '../crypto/keyring';

/**
 * Paramètres de la preuve de possession. AUCUNE valeur de terrain n'est figée
 * ici (CDC §9) : prix du flash call, disponibilité de la Silent Network
 * Authentication, plafonds réels, délais opérateur — ce sont des INCONNUES qui
 * appartiennent à Kevin. On paramètre ; on ne devine pas.
 */
export interface PhoneConfig {
  codeDigits: number;
  codeTtlSeconds: number;
  maxAttempts: number;
  /** Plafond par LIGNE (jamais par compte) : il protège le téléphone d'un TIERS. */
  lineCap: number;
  lineCapWindowSeconds: number;
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

export function assemblePhoneConfig(env: NodeJS.ProcessEnv = process.env): PhoneConfig {
  const violations: string[] = [];
  const config: PhoneConfig = {
    codeDigits: readInt(env, 'PROOF_CODE_DIGITS', 6, violations),
    codeTtlSeconds: readInt(env, 'PROOF_CODE_TTL_SECONDS', 300, violations),
    maxAttempts: readInt(env, 'PROOF_MAX_ATTEMPTS', 3, violations),
    lineCap: readInt(env, 'PROOF_LINE_CAP', 3, violations),
    lineCapWindowSeconds: readInt(env, 'PROOF_LINE_CAP_WINDOW_SECONDS', 86400, violations),
  };
  if (config.codeDigits < 4 || config.codeDigits > 10) {
    violations.push(`PROOF_CODE_DIGITS hors bornes : ${config.codeDigits} (4 à 10)`);
  }
  if (violations.length > 0) {
    throw new ConfigViolations(violations);
  }
  return config;
}

/**
 * GARDE DE BOOT — le trousseau d'empreinte du service DOIT être aligné avec la
 * référence gravée en base (006). Sans elle, un service mal configuré
 * écrirait des empreintes que le trigger rejetterait une à une, en
 * production, sans que personne comprenne pourquoi : les familles ne
 * pourraient plus déclarer un numéro, et la cause serait invisible.
 * Ici, le service REFUSE de démarrer, et dit exactement ce qui cloche.
 */
export async function assertFingerprintKeyAligned(
  pool: Pool,
  crypto: CryptoAssembly,
): Promise<void> {
  const result = await pool.query<{ hmac_key_id: string }>(
    'SELECT active_hmac_key_id() AS hmac_key_id',
  );
  const inDatabase = result.rows[0]?.hmac_key_id;
  const inService = crypto.fingerprint.activeKeyId;
  if (inDatabase !== inService) {
    throw new ConfigViolations([
      `clé d'empreinte désalignée : le service écrit sous « ${inService} », la base exige ` +
        `« ${inDatabase ?? '(aucune)'} » — une rotation de clé HMAC est une migration signée ` +
        '(elle déchiffre et re-hache toute la PII), jamais un changement de variable',
    ]);
  }
}
