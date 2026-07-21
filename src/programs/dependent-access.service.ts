import { Pool } from 'pg';
import { generatePublicIdentifier } from '../accounts/public-identifier';
import type { CryptoAssembly } from '../crypto/keyring';
import {
  CivilIdentityError,
  encryptCivilIdentity,
  generateErasureSalt,
  type PersonCivilIdentity,
} from '../crypto/person-identity';
import { dbErrorCode } from '../db/errors';
import { buildPhoneColumns, normalizePhone } from '../phone/phone-columns';
import type { ProgramOperationsConfig } from './program-operations-config';
import { hashReference, type ReferenceKeyring } from './reference-hmac';

/**
 * LE CLIC (étape 3) : un programme en mode accordé déclare un ayant droit —
 * la personne naît avec son droit, l'invitation part vers la ligne du
 * responsable (021, une transaction en base).
 *
 * ⚠️ ZÉRO LOG ICI — et pas seulement « zéro PII » : le payload porte une
 * identité civile EN CLAIR, un numéro EN CLAIR et une référence de programme
 * qui PEUT porter de la PII (§3.2). Ce service ne journalise RIEN — un test
 * le prouve en comptant les appels console.
 *
 * BOLA de programme : programId vient du MUR de l'étape 1 (jeton signé),
 * jamais d'un paramètre — ce service le reçoit déjà tranché.
 */
export type OpenDependentAccessResult =
  /** Uniforme : numéro connu ou non, invitation vive ou silencieuse — même accusé. */
  | { outcome: 'ACCEPTED'; dependentIdentifier: string }
  /** Adulte certain : ce chemin est celui des mineurs — voir /v1/grants. */
  | { outcome: 'OF_AGE' }
  | { outcome: 'NOT_GRANTED_MODE' }
  | { outcome: 'FORBIDDEN' }
  | { outcome: 'THROTTLED' }
  | { outcome: 'INVALID_PHONE' }
  | { outcome: 'INVALID_IDENTITY'; reason: string };

export const DEPENDENT_ACCESS_SERVICE = 'DEPENDENT_ACCESS_SERVICE';

const MAX_IDENTIFIER_DRAWS = 5;

export class DependentAccessService {
  constructor(
    private readonly pool: Pool,
    private readonly crypto: CryptoAssembly,
    private readonly references: ReferenceKeyring,
    private readonly config: ProgramOperationsConfig,
    private readonly generatePersonIdentifier: () => string = generatePublicIdentifier,
  ) {}

  async open(
    programId: string,
    reference: string,
    dependent: PersonCivilIdentity,
    responsiblePhone: string,
  ): Promise<OpenDependentAccessResult> {
    const phone = normalizePhone(responsiblePhone);
    if (phone === null) {
      // Une forme invalide ne parle que de la REQUÊTE, pas d'un tiers : le
      // refus propre est dû (façade §3.1) — le sans-oracle ne couvre que
      // « connu / inconnu », jamais « difforme ».
      return { outcome: 'INVALID_PHONE' };
    }

    const salt = generateErasureSalt();
    let encrypted;
    try {
      encrypted = encryptCivilIdentity(this.crypto.encryption, salt, dependent);
    } catch (err) {
      if (err instanceof CivilIdentityError) {
        // Les messages de person-identity sont garantis sans PII.
        return { outcome: 'INVALID_IDENTITY', reason: err.message };
      }
      throw err;
    }

    const line = buildPhoneColumns(this.crypto, phone);
    const ref = hashReference(this.references, reference);

    let identifier = this.generatePersonIdentifier();
    for (let draw = 0; draw < MAX_IDENTIFIER_DRAWS; draw += 1) {
      try {
        const result = await this.pool.query<{
          dependent_public_identifier: string | null;
          invitation_id: string | null;
          verdict: string;
        }>(
          'SELECT * FROM open_dependent_access($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)',
          [
            programId,
            identifier,
            salt,
            encrypted.token,
            encrypted.encKeyId,
            encrypted.birthYear,
            line.phoneHmac,
            line.hmacKeyId,
            ref.hmac,
            ref.keyId,
            this.config.dependentInvitationTtlSeconds,
            this.config.inviteClientCap,
            this.config.inviteClientCapWindowSeconds,
            this.config.inviteLineCap,
            this.config.inviteLineCapWindowSeconds,
          ],
        );
        const row = result.rows[0];
        switch (row?.verdict) {
          case 'OPENED':
          case 'OPENED_EXISTING':
            // Rejeu et première fois rendent LA MÊME forme : le programme
            // retient l'identifiant, c'est tout ce qu'il a à savoir.
            return {
              outcome: 'ACCEPTED',
              dependentIdentifier: row.dependent_public_identifier as string,
            };
          case 'OF_AGE':
            return { outcome: 'OF_AGE' };
          case 'NOT_GRANTED_MODE':
            return { outcome: 'NOT_GRANTED_MODE' };
          case 'REFUSED_CLIENT_CAP':
            return { outcome: 'THROTTLED' };
          default:
            // UNKNOWN_PROGRAM : le programme du jeton n'existe plus ou n'est
            // plus proposé — rien d'autre à dire.
            return { outcome: 'FORBIDDEN' };
        }
      } catch (err) {
        if (isIdentifierCollision(err)) {
          identifier = this.generatePersonIdentifier();
          continue;
        }
        throw err;
      }
    }
    throw new Error('ayant droit : identifiant unique introuvable après plusieurs tirages');
  }
}

function isIdentifierCollision(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    dbErrorCode(err) === '23505' &&
    'constraint' in err &&
    (err as { constraint?: unknown }).constraint === 'uq_persons_public_identifier'
  );
}
