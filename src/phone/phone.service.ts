import { Pool } from 'pg';
import { encrypt } from '../crypto/aes-gcm';
import { fingerprintOf } from '../crypto/fingerprint';
import type { CryptoAssembly } from '../crypto/keyring';
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
import type { PhoneConfig } from './phone-config';
import { resolveVerifiedAddress } from './verified-address';

export type DeclareResult =
  | { outcome: 'DECLARED'; claimId: string }
  | { outcome: 'INVALID_PHONE' };

export type RequestProofResult =
  | { outcome: 'SENT'; proofId: string }
  | { outcome: 'REFUSED_CAP' }
  | { outcome: 'REFUSED_PENDING' }
  | { outcome: 'REFUSED_CLAIM' }
  | { outcome: 'UNDELIVERABLE' }
  | { outcome: 'INTEGRITY_VIOLATION' }
  | { outcome: 'NOT_FOUND' };

export type VerifyResult = {
  outcome: 'PROVEN' | 'WRONG' | 'EXPIRED' | 'EXHAUSTED' | 'ALREADY_SETTLED' | 'NOT_FOUND';
};

export const PHONE_SERVICE = 'PHONE_SERVICE';

interface ClaimRow {
  id: string;
  account_id: string;
  phone_hmac: string;
  hmac_key_id: string;
  enc_key_id: string;
  status: string;
}

/**
 * Le téléphone : déclaration, demande de preuve, vérification.
 *
 * VÉRIFICATION PARESSEUSE (CDC §6.3) : déclarer un numéro n'envoie RIEN. La
 * preuve se demande au moment où le compte veut PAYER — jamais à
 * l'inscription. Le coût des canaux suit ainsi le revenu, pas la base
 * d'utilisateurs (SMS ≈ 0,25 $ : vérifier 500 parents = 35 % du revenu d'une
 * école). Aucun endpoint d'authentification ne peut déclencher un envoi : le
 * login ne connaît pas ce service.
 *
 * ⚠️⚠️ P4 — LE SEUL INVARIANT QUE LA BASE NE PEUT PAS TENIR, ET IL EST LE PLUS
 * DANGEREUX DU LOT.
 * `phone_hmac` et `phone_encrypted` sont deux colonnes indépendantes. Aucun
 * CHECK, aucun trigger ne peut vérifier qu'elles parlent du même numéro : la
 * base n'a pas les clés, et c'est délibéré (zéro PII déchiffrable en base).
 * Un bug de câblage — deux variables inversées, un refactor malheureux —
 * produirait une revendication qui VERROUILLE la ligne A et ENVERRAIT le code
 * au numéro B. Le registre serait cohérent, les invariants verts, et un
 * inconnu recevrait le code d'une autre famille.
 * Trois garde-fous, faute de pouvoir descendre en base :
 *   1. UN SEUL POINT DE CONSTRUCTION (`buildPhoneColumns`) : les deux colonnes
 *      naissent ensemble, d'un seul argument. Aucun appelant ne les fabrique
 *      séparément.
 *   2. RE-DÉRIVATION À L'USAGE : au moment d'ouvrir une preuve — le seul
 *      moment où l'on déchiffre — on recalcule l'empreinte à partir du clair
 *      déchiffré et on la compare à celle qui est stockée. Divergence → refus,
 *      alerte, ZÉRO appel au fournisseur. Le mensonge ne peut jamais atteindre
 *      un téléphone.
 *   3. Un test dédié forge une revendication incohérente et prouve que rien
 *      ne part (comptage d'appels sur le prover).
 */
export class PhoneService {
  constructor(
    private readonly pool: Pool,
    private readonly crypto: CryptoAssembly,
    private readonly codeKeyring: ProofCodeKeyring,
    private readonly prover: LineOwnershipProver,
    private readonly config: PhoneConfig,
  ) {}

  /** P4 §1 — LE point de construction unique des deux colonnes sensibles. */
  private buildPhoneColumns(phone: string): {
    phoneHmac: string;
    hmacKeyId: string;
    phoneEncrypted: string;
    encKeyId: string;
  } {
    const fingerprint = fingerprintOf(this.crypto.fingerprint, phone);
    return {
      phoneHmac: fingerprint.value,
      hmacKeyId: fingerprint.hmacKeyId,
      phoneEncrypted: encrypt(this.crypto.encryption, phone),
      encKeyId: this.crypto.encryption.activeKeyId,
    };
  }

  /**
   * Normalisation E.164 minimale. Le numéro n'existe en clair que dans cette
   * pile d'appels — jamais en base, jamais en log.
   */
  private normalize(raw: string): string | null {
    const trimmed = raw.replace(/[\s().-]/g, '');
    return /^\+[1-9][0-9]{7,14}$/.test(trimmed) ? trimmed : null;
  }

  /** Déclarer un numéro : on chiffre, on hache, on n'envoie RIEN (paresseux). */
  async declare(accountId: string, rawPhone: string): Promise<DeclareResult> {
    const phone = this.normalize(rawPhone);
    if (phone === null) {
      return { outcome: 'INVALID_PHONE' };
    }
    const columns = this.buildPhoneColumns(phone);

    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      // Une seule revendication VIVANTE par compte (Q3) : déclarer un autre
      // numéro révoque la précédente — jamais de PII de tiers accumulée.
      await client.query(
        `UPDATE phone_claims SET status = 'REVOKED', revoke_reason = 'REPLACED'
          WHERE account_id = $1 AND status = 'PENDING'`,
        [accountId],
      );
      const inserted = await client.query<{ id: string }>(
        `INSERT INTO phone_claims (account_id, phone_hmac, hmac_key_id, phone_encrypted, enc_key_id)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [
          accountId,
          columns.phoneHmac,
          columns.hmacKeyId,
          columns.phoneEncrypted,
          columns.encKeyId,
        ],
      );
      await client.query('COMMIT');
      const claimId = inserted.rows[0]?.id;
      if (claimId === undefined) {
        throw new Error('déclaration : aucune ligne rendue');
      }
      return { outcome: 'DECLARED', claimId };
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  /**
   * Demander une preuve de possession — au PREMIER PAIEMENT, jamais à
   * l'inscription. §3.13 : on réserve, on COMMIT, on appelle le fournisseur
   * (hors transaction), on écrit le verdict dans une transaction NEUVE.
   */
  async requestProof(
    accountId: string,
    claimId: string,
    channel: ProofChannel,
  ): Promise<RequestProofResult> {
    // BOLA : la revendication doit appartenir au compte du jeton signé.
    const claim = await this.findOwnClaim(accountId, claimId);
    if (claim === null) {
      return { outcome: 'NOT_FOUND' };
    }

    // LE POINT UNIQUE DE DÉCHIFFREMENT (P4/F4) : il résout, déchiffre,
    // RE-DÉRIVE l'empreinte et refuse toute divergence. Le numéro n'existe en
    // clair que dans cette variable, pour la durée de l'appel.
    // requireActive = false : on ouvre une preuve sur une revendication
    // PENDING — c'est précisément ce qui l'activera.
    const resolution = await resolveVerifiedAddress(this.pool, this.crypto, claim.id, false);
    if (resolution.outcome !== 'RESOLVED') {
      return { outcome: 'INTEGRITY_VIOLATION' };
    }
    const phone = resolution.phone;

    const code = generateProofCode(this.config.codeDigits);
    const hashed = hashProofCode(this.codeKeyring, code);

    // 1) RÉSERVER (la base plafonne, sérialise, trace le refus) puis COMMIT.
    const opened = await this.pool.query<{ proof_id: string | null; verdict: string }>(
      'SELECT * FROM open_possession_proof($1, $2, $3, $4, $5, $6, $7, $8)',
      [
        claimId,
        channel,
        hashed.hmac,
        hashed.keyId,
        this.config.codeTtlSeconds,
        this.config.maxAttempts,
        this.config.lineCap,
        this.config.lineCapWindowSeconds,
      ],
    );
    const verdict = opened.rows[0]?.verdict;
    const proofId = opened.rows[0]?.proof_id ?? null;
    if (verdict !== 'OPENED' || proofId === null) {
      switch (verdict) {
        case 'REFUSED_CAP':
          return { outcome: 'REFUSED_CAP' };
        case 'REFUSED_PENDING':
          return { outcome: 'REFUSED_PENDING' };
        case 'REFUSED_CLAIM':
          return { outcome: 'REFUSED_CLAIM' };
        default:
          return { outcome: 'NOT_FOUND' };
      }
    }

    // 2) APPELER le fournisseur — HORS de toute transaction (§3.13).
    try {
      const delivered = await this.prover.deliver({ channel, phone, code });
      // 3) Le VERDICT dans une transaction NEUVE : la ligne de coût et la
      //    référence naissent ensemble (P6).
      await this.pool.query('SELECT record_proof_dispatch($1, $2, $3)', [
        proofId,
        accountId,
        delivered.providerRef,
      ]);
      return { outcome: 'SENT', proofId };
    } catch (err) {
      if (err instanceof DeliveryFailed) {
        // Rien n'est parti : aucune ligne de coût, et la preuve se clôt.
        await this.pool.query('SELECT abandon_possession_proof($1, $2)', [proofId, accountId]);
        return { outcome: 'UNDELIVERABLE' };
      }
      throw err;
    }
  }

  /** Présenter le code reçu. Le service ne compare RIEN : la base tranche. */
  async verify(accountId: string, claimId: string, code: string): Promise<VerifyResult> {
    const claim = await this.findOwnClaim(accountId, claimId);
    if (claim === null) {
      return { outcome: 'NOT_FOUND' };
    }
    const proof = await this.pool.query<{ proof_code_key_id: string }>(
      "SELECT proof_code_key_id FROM possession_proofs WHERE claim_id = $1 AND status = 'PENDING'",
      [claimId],
    );
    const keyId = proof.rows[0]?.proof_code_key_id;
    if (keyId === undefined) {
      // Aucune preuve EN COURS. Deux situations très différentes pour
      // l'exploitation : rien n'a jamais été demandé (NOT_FOUND), ou tout a
      // été tranché (ALREADY_SETTLED — code déjà utilisé, essais épuisés,
      // délai dépassé). La réponse au client reste la MÊME (refus unique) ;
      // seul le verdict interne diffère, et il vaut de l'or au support.
      const settled = await this.pool.query(
        'SELECT id FROM possession_proofs WHERE claim_id = $1 LIMIT 1',
        [claimId],
      );
      return { outcome: settled.rows.length > 0 ? 'ALREADY_SETTLED' : 'NOT_FOUND' };
    }
    const hmac = hashProofCodeUnder(this.codeKeyring, keyId, code);
    if (hmac === null) {
      return { outcome: 'NOT_FOUND' };
    }

    const result = await this.pool.query<{ verdict: string }>(
      'SELECT * FROM verify_possession_code($1, $2)',
      [claimId, hmac],
    );
    const verdict = result.rows[0]?.verdict;
    switch (verdict) {
      case 'PROVEN':
      case 'WRONG':
      case 'EXPIRED':
      case 'EXHAUSTED':
      case 'ALREADY_SETTLED':
        return { outcome: verdict };
      default:
        return { outcome: 'NOT_FOUND' };
    }
  }

  // BOLA (§6) : le compte vient du jeton signé, jamais du corps de la requête.
  // La clause account_id est la ceinture — un compte ne touche que ses lignes.
  private async findOwnClaim(accountId: string, claimId: string): Promise<ClaimRow | null> {
    const result = await this.pool.query<ClaimRow>(
      `SELECT id, account_id, phone_hmac, hmac_key_id, enc_key_id, status
         FROM phone_claims WHERE id = $1 AND account_id = $2`,
      [claimId, accountId],
    );
    return result.rows[0] ?? null;
  }

}
