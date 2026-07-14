import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import type { EncryptionKey, Keyring } from './keyring';

/**
 * Chiffrement au repos de la PII : AES-256-GCM, IV aléatoire par message,
 * tag d'authentification vérifié (patron payment-core). Le jeton porte son
 * enc_key_id : une rotation de clé de chiffrement laisse les anciennes
 * valeurs déchiffrables — c'est tout l'intérêt d'un trousseau.
 *
 * Forme du jeton : v1.<key_id>.<iv b64url>.<tag b64url>.<ciphertext b64url>
 * Le key_id voyage EN CLAIR (c'est un identifiant, pas un secret) et sert
 * aussi de donnée authentifiée additionnelle : substituer un jeton chiffré
 * sous une autre clé casse la vérification du tag.
 *
 * Aucune valeur en clair ne transite par un message d'erreur, jamais.
 */
const VERSION = 'v1';
const IV_BYTES = 12; // 96 bits : la taille recommandée pour GCM
const TAG_BYTES = 16;

export class DecryptionError extends Error {
  constructor(reason: string) {
    // Jamais le jeton, jamais le clair, jamais la clé — seulement la raison.
    super(`déchiffrement impossible : ${reason}`);
    this.name = 'DecryptionError';
  }
}

export function encrypt(keyring: Keyring<EncryptionKey>, plaintext: string): string {
  const key = keyring.active();
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key.material, iv);
  cipher.setAAD(Buffer.from(`${VERSION}.${key.keyId}`, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [
    VERSION,
    key.keyId,
    iv.toString('base64url'),
    tag.toString('base64url'),
    ciphertext.toString('base64url'),
  ].join('.');
}

export function decrypt(keyring: Keyring<EncryptionKey>, token: string): string {
  const parts = token.split('.');
  if (parts.length !== 5) {
    throw new DecryptionError('forme du jeton inattendue');
  }
  const [version, keyId, ivPart, tagPart, cipherPart] = parts as [
    string,
    string,
    string,
    string,
    string,
  ];
  if (version !== VERSION) {
    throw new DecryptionError(`version « ${version} » inconnue`);
  }

  const key = keyring.get(keyId);
  if (key === undefined) {
    // Le key_id est un identifiant, pas un secret : le nommer aide
    // l'exploitation à voir qu'une clé manque au trousseau.
    throw new DecryptionError(`clé « ${keyId} » absente du trousseau`);
  }

  const iv = Buffer.from(ivPart, 'base64url');
  const tag = Buffer.from(tagPart, 'base64url');
  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
    throw new DecryptionError('IV ou tag de taille invalide');
  }

  try {
    const decipher = createDecipheriv('aes-256-gcm', key.material, iv);
    decipher.setAAD(Buffer.from(`${version}.${keyId}`, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([
      decipher.update(Buffer.from(cipherPart, 'base64url')),
      decipher.final(),
    ]).toString('utf8');
  } catch {
    // Tag invalide = altération ou mauvaise clé. On ne dit pas laquelle.
    throw new DecryptionError('authentification du message échouée');
  }
}

/** L'identifiant de clé porté par un jeton — sans le déchiffrer. */
export function keyIdOf(token: string): string | null {
  const parts = token.split('.');
  return parts.length === 5 && parts[0] === VERSION ? (parts[1] ?? null) : null;
}
