import { Pool } from 'pg';
import { generatePublicIdentifier } from '../accounts/public-identifier';
import type { AuthAssembly } from '../auth/auth-config';
import type { AuthenticationProvider } from '../auth/authentication-provider';
import type { LoginThrottle } from '../auth/login-throttle';
import type { CryptoAssembly } from '../crypto/keyring';
import { CivilIdentityIntegrityError, decryptCivilIdentity } from '../crypto/person-identity';
import { dbErrorCode } from '../db/errors';
import { buildPhoneColumns, normalizePhone } from '../phone/phone-columns';
import type { PhoneConfig } from '../phone/phone-config';
import { resolveVerifiedAddress } from '../phone/verified-address';
import {
  DeliveryFailed,
  type LineOwnershipProver,
  type ProofChannel,
} from '../proving/line-ownership-prover';
import {
  generateProofCode,
  hashProofCode,
  hashProofCodeUnder,
  type ProofCodeKeyring,
} from '../proving/proof-code';

/**
 * Réponse UNIFORME de l'ouverture (sans oracle, patron 012) : un identifiant
 * inconnu, une personne déjà autonome, un mineur trop jeune et une ouverture
 * réussie rendent LA MÊME réponse. Le seul refus distinct est le throttle.
 */
export type StartEmancipationResult = { outcome: 'ACCEPTED' } | { outcome: 'THROTTLED' };

export type CompleteEmancipationResult =
  | { outcome: 'EMANCIPATED'; accountIdentifier: string }
  /** Uniforme : personne inconnue, code faux, ligne non prouvée, trop jeune… */
  | { outcome: 'REFUSED' }
  | { outcome: 'SECRET_TOO_SHORT'; minLength: number }
  | { outcome: 'THROTTLED' };

export const EMANCIPATION_SERVICE = 'EMANCIPATION_SERVICE';

const MAX_IDENTIFIER_DRAWS = 5;

/**
 * L'ÉMANCIPATION (LOT 5, étape 7) : le jeune prouve SA ligne et acquiert son
 * compte — même person_id, coupure nette. Les murs sont EN BASE (020 : âge,
 * ligne prouvée, invariant E au commit, irréversibilité C11) ; ce service
 * orchestre : throttle IP, réponse sans oracle, preuve §3.13 (réserver →
 * COMMIT → appeler le fournisseur → verdict en transaction neuve), zéro PII
 * dans les logs.
 *
 * Le demandeur n'est PAS authentifié (il n'a pas encore de compte — c'est
 * tout le sujet) : les endpoints sont publics, throttlés par IP, et le vrai
 * mur anti-abus est celui du LOT 2 — le plafond par LIGNE, en base.
 */
export class EmancipationService {
  constructor(
    private readonly pool: Pool,
    private readonly crypto: CryptoAssembly,
    private readonly codeKeyring: ProofCodeKeyring,
    private readonly prover: LineOwnershipProver,
    private readonly phoneConfig: PhoneConfig,
    private readonly provider: AuthenticationProvider,
    private readonly authConfig: AuthAssembly,
    private readonly throttle: LoginThrottle,
    private readonly generateAccountIdentifier: () => string = generatePublicIdentifier,
  ) {}

  /**
   * Ouvre l'émancipation : la revendication naît pour la personne (mur d'âge
   * en base), le code part sur la ligne déclarée. Réponse uniforme.
   */
  async start(
    personPublicIdentifier: string,
    rawPhone: string,
    channel: ProofChannel,
    clientIp: string,
  ): Promise<StartEmancipationResult> {
    if (!this.throttle.allowByKey(clientIp)) {
      return { outcome: 'THROTTLED' };
    }
    const phone = normalizePhone(rawPhone);
    if (phone === null) {
      return { outcome: 'ACCEPTED' }; // uniforme : rien à sonder
    }

    // LA FAÇADE AU JOUR PRÈS (D-C, symétrique de 017) : le mur en base n'a
    // que l'année et accepte >= — jamais plus dur. Ici on lit la date
    // complète par le chemin contrôlé et on resserre : pas un SMS ne part
    // pour un jeune qui n'a pas SES seize ans révolus. Réponse uniforme.
    const personId = await this.personIdOf(personPublicIdentifier);
    if (personId === null || !(await this.exactlyOfAge(personId))) {
      return { outcome: 'ACCEPTED' };
    }
    const columns = buildPhoneColumns(this.crypto, phone);

    const opened = await this.pool.query<{ claim_id: string | null; verdict: string }>(
      'SELECT * FROM open_emancipation($1, $2, $3, $4, $5)',
      [
        personPublicIdentifier,
        columns.phoneHmac,
        columns.hmacKeyId,
        columns.phoneEncrypted,
        columns.encKeyId,
      ],
    );
    const claimId = opened.rows[0]?.claim_id ?? null;
    if (opened.rows[0]?.verdict !== 'OPENED' || claimId === null) {
      // UNKNOWN / HAS_ACCOUNT / UNDERAGE : le verdict interne vaut de l'or au
      // support ; la réponse externe ne distingue RIEN.
      return { outcome: 'ACCEPTED' };
    }

    // La preuve, patron LOT 2 intégral : le point unique de déchiffrement
    // re-dérive (P4), la base plafonne PAR LIGNE, l'appel réseau vit hors
    // transaction (§3.13), le coût ne naît que si le fournisseur accepte.
    const resolution = await resolveVerifiedAddress(this.pool, this.crypto, claimId, false);
    if (resolution.outcome !== 'RESOLVED') {
      return { outcome: 'ACCEPTED' }; // l'incident est déjà tracé (INTÉGRITÉ)
    }

    const code = generateProofCode(this.phoneConfig.codeDigits);
    const hashed = hashProofCode(this.codeKeyring, code);
    const proof = await this.pool.query<{ proof_id: string | null; verdict: string }>(
      'SELECT * FROM open_possession_proof($1, $2, $3, $4, $5, $6, $7, $8)',
      [
        claimId,
        channel,
        hashed.hmac,
        hashed.keyId,
        this.phoneConfig.codeTtlSeconds,
        this.phoneConfig.maxAttempts,
        this.phoneConfig.lineCap,
        this.phoneConfig.lineCapWindowSeconds,
      ],
    );
    const proofId = proof.rows[0]?.proof_id ?? null;
    if (proof.rows[0]?.verdict !== 'OPENED' || proofId === null) {
      return { outcome: 'ACCEPTED' }; // plafond, preuve en cours… rien à sonder
    }

    try {
      const delivered = await this.prover.deliver({ channel, phone: resolution.phone, code });
      await this.pool.query('SELECT record_proof_dispatch($1, $2, $3)', [
        proofId,
        personId,
        delivered.providerRef,
      ]);
    } catch (err) {
      if (err instanceof DeliveryFailed) {
        await this.pool.query('SELECT abandon_possession_proof($1, $2)', [proofId, personId]);
      } else {
        throw err;
      }
    }
    return { outcome: 'ACCEPTED' };
  }

  /**
   * Achève l'émancipation : code vérifié (la base compte les essais), secret
   * posé, compte né — même person_id — et coupure nette au commit.
   */
  async complete(
    personPublicIdentifier: string,
    code: string,
    secret: string,
    clientIp: string,
  ): Promise<CompleteEmancipationResult> {
    if (!this.throttle.allowByKey(clientIp)) {
      return { outcome: 'THROTTLED' };
    }
    // Façade avant tout coût argon2 — la seule réponse non uniforme, car elle
    // ne révèle rien sur la personne, seulement sur la requête.
    if (secret.length < this.authConfig.secretMinLength) {
      return { outcome: 'SECRET_TOO_SHORT', minLength: this.authConfig.secretMinLength };
    }

    const personId = await this.personIdOf(personPublicIdentifier);
    if (personId === null) {
      return { outcome: 'REFUSED' };
    }
    // La façade au jour près, re-jouée à l'acte (même règle qu'à l'ouverture).
    if (!(await this.exactlyOfAge(personId))) {
      return { outcome: 'REFUSED' };
    }

    // LE CODE FRAIS EST TOUJOURS EXIGÉ : c'est LUI qui authentifie l'acte
    // (la SIM dans la main, à cet instant). Une revendication déjà ACTIVE ne
    // dispense de rien — sinon quiconque connaît l'identifiant public de la
    // personne poserait SON secret sur son dos dès que le compte meurt. La
    // preuve se vérifie et l'acte s'achève dans LA MÊME requête ; l'état
    // « prouvé mais jamais achevé » (crash entre les deux) est un cas rare
    // qui se résout par acte staff, pas par une porte sans code.
    const claim = await this.pool.query<{ id: string }>(
      `SELECT id FROM phone_claims WHERE person_id = $1 AND status = 'PENDING'`,
      [personId],
    );
    const claimRow = claim.rows[0];
    if (claimRow === undefined) {
      return { outcome: 'REFUSED' };
    }

    const proof = await this.pool.query<{ proof_code_key_id: string }>(
      "SELECT proof_code_key_id FROM possession_proofs WHERE claim_id = $1 AND status = 'PENDING'",
      [claimRow.id],
    );
    const keyId = proof.rows[0]?.proof_code_key_id;
    if (keyId === undefined) {
      return { outcome: 'REFUSED' };
    }
    const hmac = hashProofCodeUnder(this.codeKeyring, keyId, code);
    if (hmac === null) {
      return { outcome: 'REFUSED' };
    }
    const verified = await this.pool.query<{ verdict: string }>(
      'SELECT * FROM verify_possession_code($1, $2)',
      [claimRow.id, hmac],
    );
    if (verified.rows[0]?.verdict !== 'PROVEN') {
      return { outcome: 'REFUSED' };
    }

    const secretHash = await this.provider.hashSecret(secret);
    let identifier = this.generateAccountIdentifier();
    for (let draw = 0; draw < MAX_IDENTIFIER_DRAWS; draw += 1) {
      try {
        const result = await this.pool.query<{ account_id: string | null; verdict: string }>(
          'SELECT * FROM complete_emancipation($1, $2, $3)',
          [personId, identifier, secretHash],
        );
        if (result.rows[0]?.verdict === 'EMANCIPATED') {
          return { outcome: 'EMANCIPATED', accountIdentifier: identifier };
        }
        return { outcome: 'REFUSED' }; // UNDERAGE / HAS_ACCOUNT / LINE_NOT_PROVEN
      } catch (err) {
        if (isCollision(err, 'uq_accounts_public_identifier')) {
          identifier = this.generateAccountIdentifier();
          continue;
        }
        throw err;
      }
    }
    throw new Error('émancipation : identifiant unique introuvable après plusieurs tirages');
  }

  private async personIdOf(publicIdentifier: string): Promise<string | null> {
    const result = await this.pool.query<{ id: string }>(
      'SELECT id FROM persons WHERE public_identifier = $1',
      [publicIdentifier],
    );
    return result.rows[0]?.id ?? null;
  }

  /**
   * L'âge EXACT (façade §3.1) : la date complète, lue par le chemin contrôlé
   * et déchiffrée avec re-dérivation (C4). Sans identité fournie, le mur
   * d'année de la base reste seul juge (il refuse déjà les cas grossiers).
   */
  private async exactlyOfAge(personId: string): Promise<boolean> {
    const stored = await this.pool.query<{
      civil_identity_encrypted: string | null;
      erasure_salt: Buffer;
      birth_year: number | null;
    }>(
      'SELECT civil_identity_encrypted, erasure_salt, birth_year FROM read_person_identity($1)',
      [personId],
    );
    const row = stored.rows[0];
    if (row === undefined) {
      return false;
    }
    if (row.civil_identity_encrypted === null || row.birth_year === null) {
      return true; // pas de date complète : le mur d'année tranche seul
    }
    let birthDate: string;
    try {
      birthDate = decryptCivilIdentity(
        this.crypto.encryption,
        row.erasure_salt,
        row.civil_identity_encrypted,
        row.birth_year,
      ).birthDate;
    } catch (err) {
      if (err instanceof CivilIdentityIntegrityError) {
        return false; // l'incident est déjà tracé — on n'émancipe pas sur un registre qui ment
      }
      throw err;
    }

    const threshold = await this.pool.query<{ age: number }>(
      'SELECT emancipation_minimum_age() AS age',
    );
    const minimumAge = threshold.rows[0]?.age;
    if (minimumAge === undefined) {
      return false;
    }
    return exactAgeInYears(birthDate) >= minimumAge;
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

function isCollision(err: unknown, constraint: string): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    dbErrorCode(err) === '23505' &&
    'constraint' in err &&
    (err as { constraint?: unknown }).constraint === constraint
  );
}
