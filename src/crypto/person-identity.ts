import { hkdfSync, randomBytes } from 'crypto';
import { decrypt, encrypt } from './aes-gcm';
import type { EncryptionKey, Keyring } from './keyring';

/**
 * L'identité d'état civil d'une PERSONNE (LOT 5) — le SEUL module qui la
 * chiffre et la déchiffre (motif F : decrypt( vit dans src/crypto/).
 *
 * Finalité écrite (CDC §2.1.1.5) : « identité d'état civil, source unique
 * pour tous les programmes ». Protection maximale : le blob ne quitte jamais
 * ce module en clair vers un log, un jeton ou un message d'erreur.
 *
 * LE NOM, agnostique du pays (motif G) : des composantes GÉNÉRIQUES, dans
 * l'ordre fourni par le déclarant, plus un nom d'affichage FOURNI. Ce module
 * STOCKE, il n'interprète pas — il ne sait pas ce qu'est un post-nom, un
 * deuxième prénom ou un nom d'usage, et ne doit jamais le savoir.
 *
 * EFFACEMENT PAR PERSONNE (§3.14) : la clé de chiffrement est DÉRIVÉE
 * (HKDF-SHA256) de la clé du trousseau ET d'un sel propre à la personne.
 * Détruire le sel rend le blob illisible à jamais — sans toucher ni au
 * trousseau ni aux autres personnes. La dérivation est standard (RFC 5869,
 * crypto de Node) : zéro crypto maison.
 *
 * DISCIPLINE DU SEUL ÉCRIVAIN : birth_year (la borne d'âge en clair, 014) est
 * CALCULÉ ICI, à partir de la même date que le blob. Aucun appelant ne le
 * recalcule jamais lui-même : c'est ce qui empêche la colonne et le blob de
 * mentir l'un sur l'autre (la base n'a pas les clés, elle ne peut pas tenir
 * cette cohérence — même raison d'être que la re-dérivation du motif F).
 */

export const ERASURE_SALT_BYTES = 32;

const HKDF_INFO = 'user-core/person-identity/v1';
const BLOB_VERSION = 1;
const MAX_NAME_COMPONENTS = 8;
const MAX_COMPONENT_LENGTH = 80;
const MAX_DISPLAY_NAME_LENGTH = 80; // même borne que account_profiles (011)
const MIN_BIRTH_YEAR = 1900; // cohérent avec chk_persons_birth_year_range (014)
const BIRTH_DATE_SHAPE = /^\d{4}-\d{2}-\d{2}$/;

export interface PersonCivilIdentity {
  /** Composantes du nom, dans l'ordre FOURNI. Aucune sémantique par position. */
  nameComponents: string[];
  /** Le nom d'affichage est FOURNI, jamais recomposé par le cœur. */
  displayName: string;
  /** Date de naissance complète, forme AAAA-MM-JJ. */
  birthDate: string;
}

export class CivilIdentityError extends Error {
  // Jamais un nom, jamais une date, jamais le blob — seulement la raison.
  constructor(reason: string) {
    super(`identité civile : ${reason}`);
    this.name = 'CivilIdentityError';
  }
}

/** Le sel d'effacement d'une personne : CSPRNG, une fois, à la création. */
export function generateErasureSalt(): Buffer {
  return randomBytes(ERASURE_SALT_BYTES);
}

// La dérivée conserve le keyId du trousseau : le jeton chiffré porte donc
// l'enc_key_id du trousseau (celui que 014 stocke), et une rotation de la clé
// active laisse les anciens blobs déchiffrables — exactement comme pour les
// numéros. Le sel ne voyage jamais dans le jeton : il vit en base, hors du
// SELECT du rôle applicatif, remis par read_person_identity() seulement.
function deriveKey(master: EncryptionKey, erasureSalt: Buffer): EncryptionKey {
  const material = Buffer.from(
    hkdfSync('sha256', master.material, erasureSalt, HKDF_INFO, 32),
  );
  return { keyId: master.keyId, material } as EncryptionKey;
}

class DerivedKeyring implements Keyring<EncryptionKey> {
  readonly activeKeyId: string;

  constructor(
    private readonly master: Keyring<EncryptionKey>,
    private readonly erasureSalt: Buffer,
  ) {
    this.activeKeyId = master.activeKeyId;
  }

  get(keyId: string): EncryptionKey | undefined {
    const key = this.master.get(keyId);
    return key === undefined ? undefined : deriveKey(key, this.erasureSalt);
  }

  active(): EncryptionKey {
    return deriveKey(this.master.active(), this.erasureSalt);
  }
}

function assertSaltShape(erasureSalt: Buffer): void {
  if (erasureSalt.length !== ERASURE_SALT_BYTES) {
    throw new CivilIdentityError(
      `sel d'effacement de ${erasureSalt.length} octets, ${ERASURE_SALT_BYTES} exigés`,
    );
  }
}

function todayIsoUtc(): string {
  return new Date().toISOString().slice(0, 10);
}

// Façade (§3.1) : des erreurs PROPRES avant tout chiffrement. Les murs
// porteurs (paire blob/clé, borne d'année, set-once) restent en base (014).
function validateIdentity(identity: PersonCivilIdentity): void {
  if (
    !Array.isArray(identity.nameComponents) ||
    identity.nameComponents.length < 1 ||
    identity.nameComponents.length > MAX_NAME_COMPONENTS
  ) {
    throw new CivilIdentityError(
      `entre 1 et ${MAX_NAME_COMPONENTS} composantes de nom attendues`,
    );
  }
  for (const component of identity.nameComponents) {
    if (
      typeof component !== 'string' ||
      component.trim().length < 1 ||
      component.length > MAX_COMPONENT_LENGTH
    ) {
      throw new CivilIdentityError(
        `chaque composante de nom fait entre 1 et ${MAX_COMPONENT_LENGTH} caractères`,
      );
    }
  }
  if (
    typeof identity.displayName !== 'string' ||
    identity.displayName.trim().length < 1 ||
    identity.displayName.length > MAX_DISPLAY_NAME_LENGTH
  ) {
    throw new CivilIdentityError(
      `nom d'affichage entre 1 et ${MAX_DISPLAY_NAME_LENGTH} caractères`,
    );
  }
  if (typeof identity.birthDate !== 'string' || !BIRTH_DATE_SHAPE.test(identity.birthDate)) {
    throw new CivilIdentityError('date de naissance attendue en AAAA-MM-JJ');
  }
  // Une date qui ne se re-sérialise pas à l'identique n'existe pas (31/02…).
  const parsed = new Date(`${identity.birthDate}T00:00:00Z`);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== identity.birthDate) {
    throw new CivilIdentityError('date de naissance inexistante au calendrier');
  }
  if (identity.birthDate > todayIsoUtc()) {
    throw new CivilIdentityError('date de naissance dans le futur');
  }
  if (birthYearOf(identity.birthDate) < MIN_BIRTH_YEAR) {
    throw new CivilIdentityError(`année de naissance antérieure à ${MIN_BIRTH_YEAR}`);
  }
}

function birthYearOf(birthDate: string): number {
  return Number(birthDate.slice(0, 4));
}

export interface EncryptedCivilIdentity {
  /** Le blob pour persons.civil_identity_encrypted. */
  token: string;
  /** L'identifiant de clé du TROUSSEAU (pas la dérivée) pour persons.enc_key_id. */
  encKeyId: string;
  /** LA valeur pour persons.birth_year — jamais recalculée ailleurs. */
  birthYear: number;
}

export function encryptCivilIdentity(
  keyring: Keyring<EncryptionKey>,
  erasureSalt: Buffer,
  identity: PersonCivilIdentity,
): EncryptedCivilIdentity {
  assertSaltShape(erasureSalt);
  validateIdentity(identity);

  const token = encrypt(
    new DerivedKeyring(keyring, erasureSalt),
    JSON.stringify({
      v: BLOB_VERSION,
      nameComponents: identity.nameComponents,
      displayName: identity.displayName,
      birthDate: identity.birthDate,
    }),
  );
  return {
    token,
    encKeyId: keyring.activeKeyId,
    birthYear: birthYearOf(identity.birthDate),
  };
}

export function decryptCivilIdentity(
  keyring: Keyring<EncryptionKey>,
  erasureSalt: Buffer,
  token: string,
): PersonCivilIdentity {
  assertSaltShape(erasureSalt);

  const plaintext = decrypt(new DerivedKeyring(keyring, erasureSalt), token);
  let parsed: unknown;
  try {
    parsed = JSON.parse(plaintext);
  } catch {
    throw new CivilIdentityError('blob illisible');
  }
  if (
    parsed === null ||
    typeof parsed !== 'object' ||
    (parsed as { v?: unknown }).v !== BLOB_VERSION
  ) {
    throw new CivilIdentityError('version de blob inconnue');
  }
  const candidate = parsed as {
    nameComponents?: unknown;
    displayName?: unknown;
    birthDate?: unknown;
  };
  const identity: PersonCivilIdentity = {
    nameComponents: candidate.nameComponents as string[],
    displayName: candidate.displayName as string,
    birthDate: candidate.birthDate as string,
  };
  // Le blob vient de NOUS (même module, même version) — une forme invalide
  // signale une altération que le tag GCM n'explique pas : on refuse net.
  validateIdentityShapeOnly(identity);
  return identity;
}

// À la relecture, la date « dans le futur » ne se re-juge pas (un blob écrit
// hier reste lisible demain) : seule la FORME est re-validée.
function validateIdentityShapeOnly(identity: PersonCivilIdentity): void {
  if (
    !Array.isArray(identity.nameComponents) ||
    identity.nameComponents.length < 1 ||
    identity.nameComponents.some((c) => typeof c !== 'string' || c.length < 1)
  ) {
    throw new CivilIdentityError('composantes de nom absentes du blob');
  }
  if (typeof identity.displayName !== 'string' || identity.displayName.length < 1) {
    throw new CivilIdentityError("nom d'affichage absent du blob");
  }
  if (typeof identity.birthDate !== 'string' || !BIRTH_DATE_SHAPE.test(identity.birthDate)) {
    throw new CivilIdentityError('date de naissance absente du blob');
  }
}
