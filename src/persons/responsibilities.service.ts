import { Pool } from 'pg';
import { generatePublicIdentifier } from '../accounts/public-identifier';
import type { CryptoAssembly } from '../crypto/keyring';
import {
  CivilIdentityError,
  encryptCivilIdentity,
  generateErasureSalt,
  type PersonCivilIdentity,
} from '../crypto/person-identity';
import { DB_ERROR, dbErrorCode, isDbError } from '../db/errors';

export type AttachDependentResult =
  | {
      outcome: 'OK';
      dependentPersonId: string;
      dependentPublicIdentifier: string;
      responsibilityId: string;
    }
  | { outcome: 'INVALID_IDENTITY'; reason: string }
  /** La date complète dit « majeur » : la façade tranche au jour près (§3.1). */
  | { outcome: 'DEPENDENT_NOT_MINOR' }
  | { outcome: 'ACCOUNT_NOT_ACTIVE' };

export type AddCoResponsibleResult =
  | { outcome: 'OK'; responsibilityId: string }
  | { outcome: 'NOT_RESPONSIBLE' }
  | { outcome: 'UNKNOWN_PERSON' }
  | { outcome: 'CO_RESPONSIBLE_CANNOT_ACT' }
  | { outcome: 'ALREADY_RESPONSIBLE' }
  | { outcome: 'PERSON_IS_AUTONOMOUS' };

export type EndResponsibilityResult =
  | { outcome: 'OK' }
  | { outcome: 'FORBIDDEN' }
  | { outcome: 'UNKNOWN_RESPONSIBILITY' }
  | { outcome: 'UNKNOWN_PERSON' }
  /** Clore ce lien laisserait la personne sans personne pour agir (P0114). */
  | { outcome: 'WOULD_ORPHAN' }
  | { outcome: 'REPLACEMENT_CANNOT_ACT' };

export const RESPONSIBILITIES_SERVICE = 'RESPONSIBILITIES_SERVICE';

const MAX_IDENTIFIER_DRAWS = 5;

/**
 * Le lien de responsabilité (LOT 5, étape 4). BOLA partout : le compte
 * agissant vient du jeton signé ; il n'atteint que les personnes dont sa
 * personne est responsable. Zéro log (identités = PII).
 *
 * AJOUTER un co-responsable est simple (un responsable en place le fait) ;
 * RETIRER un responsable est l'ACTE STAFF (C2/D-D) : contrôlé (rôle
 * PLATFORM_STAFF/ADMIN), tracé par le registre lui-même (ligne ENDED + motif
 * ADMIN, remplacement porté par opened_by = PLATFORM_STAFF), et ATOMIQUE —
 * l'invariant orphelin (P0114) garantit au commit qu'aucune personne ne
 * reste sans personne pour agir. Jamais un self-service : dans un conflit
 * de garde, le système ne tranche pas à la place d'un juge.
 */
export class ResponsibilitiesService {
  constructor(
    private readonly pool: Pool,
    private readonly crypto: CryptoAssembly,
    private readonly generatePersonIdentifier: () => string = generatePublicIdentifier,
  ) {}

  async attach(
    actingAccountId: string,
    identity: PersonCivilIdentity,
  ): Promise<AttachDependentResult> {
    const salt = generateErasureSalt();
    let encrypted;
    try {
      encrypted = encryptCivilIdentity(this.crypto.encryption, salt, identity);
    } catch (err) {
      if (err instanceof CivilIdentityError) {
        return { outcome: 'INVALID_IDENTITY', reason: err.message };
      }
      throw err;
    }

    // La FAÇADE au jour près : le mur en base n'a que l'année (délibérément —
    // la date complète est chiffrée) et ne refuse que l'adulte CERTAIN ;
    // ici on voit la date fournie, on tranche exactement (§3.1).
    const minimumAge = await this.minimumAge();
    if (exactAgeInYears(identity.birthDate) >= minimumAge) {
      return { outcome: 'DEPENDENT_NOT_MINOR' };
    }

    let identifier = this.generatePersonIdentifier();
    for (let draw = 0; draw < MAX_IDENTIFIER_DRAWS; draw += 1) {
      try {
        // 023 : la fonction part du COMPTE agissant (la base résout la
        // personne) et estampille elle-même l'acteur RESPONSIBLE — le
        // paramètre d'acteur a disparu de la signature.
        const result = await this.pool.query<{
          dependent_person_id: string;
          responsibility_id: string;
        }>(
          `SELECT dependent_person_id, responsibility_id
             FROM attach_dependent($1, $2, $3, $4, $5, $6)`,
          [actingAccountId, identifier, salt, encrypted.token, encrypted.encKeyId, encrypted.birthYear],
        );
        const row = result.rows[0];
        if (row === undefined) {
          throw new Error('rattachement : aucune ligne rendue');
        }
        return {
          outcome: 'OK',
          dependentPersonId: row.dependent_person_id,
          dependentPublicIdentifier: identifier,
          responsibilityId: row.responsibility_id,
        };
      } catch (err) {
        if (isUniqueViolation(err, 'uq_persons_public_identifier')) {
          identifier = this.generatePersonIdentifier();
          continue;
        }
        if (isDbError(err, DB_ERROR.DEAD_PARENT)) {
          return { outcome: 'ACCOUNT_NOT_ACTIVE' };
        }
        // Le mur d'année (P0111) ne devrait jamais parler ici : la façade
        // ci-dessus est STRICTEMENT plus dure que lui. S'il parle, c'est un
        // vrai bug — on le laisse remonter.
        throw err;
      }
    }
    throw new Error('rattachement : identifiant unique introuvable après plusieurs tirages');
  }

  async addCoResponsible(
    actingAccountId: string,
    dependentPersonId: string,
    coResponsiblePublicIdentifier: string,
  ): Promise<AddCoResponsibleResult> {
    const co = await this.pool.query<{ id: string }>(
      'SELECT id FROM persons WHERE public_identifier = $1',
      [coResponsiblePublicIdentifier],
    );
    const coPerson = co.rows[0];
    if (coPerson === undefined) {
      return { outcome: 'UNKNOWN_PERSON' };
    }

    // 023 : le BOLA « on n'ajoute un responsable qu'aux personnes dont ON est
    // responsable » se lit EN BASE (le lien actif de l'agissant est la
    // preuve, et c'est la fonction qui la consulte) ; l'acteur RESPONSIBLE
    // est estampillé par elle. FORBIDDEN (compte agissant inconnu ou
    // inactif) est rendu comme NOT_RESPONSIBLE : un compte qui ne peut pas
    // agir n'est responsable de personne — et une session vivante implique
    // déjà un compte actif.
    try {
      const result = await this.pool.query<{ verdict: string; responsibility_id: string | null }>(
        'SELECT verdict, responsibility_id FROM open_responsibility_by_responsible($1, $2, $3)',
        [actingAccountId, coPerson.id, dependentPersonId],
      );
      const row = result.rows[0];
      if (row?.verdict === 'OPENED' && row.responsibility_id !== null) {
        return { outcome: 'OK', responsibilityId: row.responsibility_id };
      }
      return { outcome: 'NOT_RESPONSIBLE' };
    } catch (err) {
      if (isDbError(err, DB_ERROR.DEAD_PARENT)) {
        return { outcome: 'CO_RESPONSIBLE_CANNOT_ACT' };
      }
      if (isDbError(err, DB_ERROR.EMANCIPATION_CUT)) {
        return { outcome: 'PERSON_IS_AUTONOMOUS' };
      }
      if (isUniqueViolation(err, 'uq_person_responsibilities_active')) {
        return { outcome: 'ALREADY_RESPONSIBLE' };
      }
      throw err;
    }
  }

  /**
   * L'ACTE STAFF (C2 option a, mur C11) : la clôture passe par
   * end_responsibility() — SECURITY DEFINER, seul chemin (le rôle applicatif
   * n'a AUCUN droit d'UPDATE sur les liens). Le contrôle de rôle vit EN BASE
   * (le rôle du staff est une donnée d'accounts) ; ce service ne fait que
   * résoudre l'identifiant du remplaçant et rendre les erreurs propres.
   * Fin + remplacement sont atomiques DANS la fonction ; les murs différés
   * (orphelin P0114, coupure P0113) rendent leur verdict au commit.
   */
  async endResponsibility(
    staffAccountId: string,
    responsibilityId: string,
    replacementResponsiblePublicIdentifier: string | null,
  ): Promise<EndResponsibilityResult> {
    let replacementPersonId: string | null = null;
    if (replacementResponsiblePublicIdentifier !== null) {
      const replacement = await this.pool.query<{ id: string }>(
        'SELECT id FROM persons WHERE public_identifier = $1',
        [replacementResponsiblePublicIdentifier],
      );
      replacementPersonId = replacement.rows[0]?.id ?? null;
      if (replacementPersonId === null) {
        return { outcome: 'UNKNOWN_PERSON' };
      }
    }
    return this.callEnd(responsibilityId, staffAccountId, replacementPersonId);
  }

  private async callEnd(
    responsibilityId: string,
    actorAccountId: string,
    replacementPersonId: string | null,
  ): Promise<EndResponsibilityResult> {
    try {
      const result = await this.pool.query<{ verdict: string }>(
        'SELECT verdict FROM end_responsibility($1, $2, $3)',
        [responsibilityId, actorAccountId, replacementPersonId],
      );
      switch (result.rows[0]?.verdict) {
        case 'ENDED':
          return { outcome: 'OK' };
        case 'FORBIDDEN':
          return { outcome: 'FORBIDDEN' };
        default:
          return { outcome: 'UNKNOWN_RESPONSIBILITY' };
      }
    } catch (err) {
      if (isDbError(err, DB_ERROR.ORPHANED_DEPENDENT)) {
        return { outcome: 'WOULD_ORPHAN' };
      }
      if (isDbError(err, DB_ERROR.DEAD_PARENT)) {
        return { outcome: 'REPLACEMENT_CANNOT_ACT' };
      }
      if (isUniqueViolation(err, 'uq_person_responsibilities_active')) {
        // Le remplaçant était déjà responsable : la fin seule suffit.
        return this.callEnd(responsibilityId, actorAccountId, null);
      }
      throw err;
    }
  }

  private async minimumAge(): Promise<number> {
    const result = await this.pool.query<{ age: number }>(
      'SELECT emancipation_minimum_age() AS age',
    );
    const row = result.rows[0];
    if (row === undefined) {
      throw new Error('seuil d’émancipation illisible');
    }
    return row.age;
  }

}

function exactAgeInYears(birthDate: string): number {
  const today = new Date().toISOString().slice(0, 10);
  const [ty, tm, td] = today.split('-').map(Number) as [number, number, number];
  const [by, bm, bd] = birthDate.split('-').map(Number) as [number, number, number];
  let age = ty - by;
  if (tm < bm || (tm === bm && td < bd)) {
    age -= 1;
  }
  return age;
}

function isUniqueViolation(err: unknown, constraint: string): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    dbErrorCode(err) === '23505' &&
    'constraint' in err &&
    (err as { constraint?: unknown }).constraint === constraint
  );
}
