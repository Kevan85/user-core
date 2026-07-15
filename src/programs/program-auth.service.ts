import { createPublicKey, verify as ed25519Verify } from 'crypto';
import { Pool } from 'pg';
import type { AuthAssembly } from '../auth/auth-config';
import type { LoginThrottle } from '../auth/login-throttle';
import type { ProgramAuthConfig } from './program-auth-config';
import { issueProgramToken } from './program-token';

export type ProgramTokenResult =
  | { outcome: 'THROTTLED' }
  | { outcome: 'REFUSED' }
  | { outcome: 'REPLAYED' }
  | { outcome: 'OK'; accessToken: string; expiresAt: Date };

export const PROGRAM_AUTH_SERVICE = 'PROGRAM_AUTH_SERVICE';

// L'audience est un CONSTANTE DE PROTOCOLE, pas une valeur de terrain : une
// assertion signée pour un AUTRE cœur (payment-core demain) ne doit jamais
// s'échanger ici, même si le programme signe des deux côtés avec la même
// paire de clés.
export const ASSERTION_AUDIENCE = 'user-core';

const JTI_SHAPE = /^[A-Za-z0-9_-]{8,128}$/;

interface AssertionHeader {
  alg?: unknown;
  kid?: unknown;
}

interface AssertionPayload {
  iss?: unknown;
  aud?: unknown;
  jti?: unknown;
  exp?: unknown;
}

interface CandidateRow {
  program_client_id: string;
  program_id: string;
  public_key: string;
}

/**
 * L'échange assertion → jeton (LOT 4, étape 6). Le programme signe avec SA
 * clé privée — que nous n'avons jamais eue — et repart avec un jeton court
 * dont le pid est LA frontière de tout /v1.
 *
 * L'identité SE DÉRIVE de la clé qui a vérifié (doctrine payment-core) :
 * iss et kid ne font que SÉLECTIONNER la candidate — annoncer le client d'un
 * autre ne sert à rien, la signature ne vérifiera pas.
 *
 * LE REJEU EST NON REPRÉSENTABLE : le jti s'INSÈRE dans
 * program_client_assertions (013) et l'unicité de la base tranche — il n'y a
 * pas de « déjà vu ? » à écrire dans le service, donc pas à oublier.
 *
 * Tous les refus rendent LE MÊME résultat (REFUSED, 401 générique) : client
 * inconnu, clé révoquée, signature fausse, assertion périmée — rien ne
 * distingue, rien ne s'énumère. Zéro log ici (ni assertion, ni jti, ni id).
 */
export class ProgramAuthService {
  constructor(
    private readonly pool: Pool,
    private readonly authConfig: AuthAssembly,
    private readonly config: ProgramAuthConfig,
    private readonly throttle: LoginThrottle,
  ) {}

  async token(assertion: string, clientIp: string): Promise<ProgramTokenResult> {
    const parsed = this.parse(assertion);
    if (parsed === null) {
      // Difforme : compte quand même sur le budget IP (un flot d'illisible
      // reste un flot), puis refus sec.
      if (!this.throttle.allowByKey(clientIp)) {
        return { outcome: 'THROTTLED' };
      }
      return { outcome: 'REFUSED' };
    }

    // Par IP ET par client VISÉ — la chaîne annoncée, qu'elle existe ou non
    // (le throttle ne révèle rien de l'existence d'un client).
    if (!this.throttle.allow(clientIp, parsed.iss)) {
      return { outcome: 'THROTTLED' };
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    if (
      parsed.exp <= nowSeconds ||
      parsed.exp > nowSeconds + this.config.assertionMaxTtlSeconds ||
      parsed.aud !== ASSERTION_AUDIENCE
    ) {
      return { outcome: 'REFUSED' };
    }

    // La candidate : LA clé ACTIVE (unique, index partiel de 010) d'un client
    // ACTIF, sous le kid annoncé.
    const candidate = await this.pool.query<CandidateRow>(
      `SELECT c.id AS program_client_id, c.program_id, k.public_key
         FROM program_clients c
         JOIN program_client_keys k ON k.program_client_id = c.id
        WHERE c.client_id = $1 AND c.status = 'ACTIVE'
          AND k.kid = $2 AND k.status = 'ACTIVE'`,
      [parsed.iss, parsed.kid],
    );
    const row = candidate.rows[0];
    if (row === undefined) {
      return { outcome: 'REFUSED' };
    }

    let authentic = false;
    try {
      authentic = ed25519Verify(
        null,
        Buffer.from(parsed.signingInput, 'utf8'),
        createPublicKey({ key: Buffer.from(row.public_key, 'base64'), format: 'der', type: 'spki' }),
        Buffer.from(parsed.signature, 'base64url'),
      );
    } catch {
      authentic = false;
    }
    if (!authentic) {
      return { outcome: 'REFUSED' };
    }

    // LE verdict de rejeu : l'INSERT. Unicité en base — 23505 = déjà vu.
    try {
      await this.pool.query(
        `INSERT INTO program_client_assertions (program_client_id, jti, expires_at)
         VALUES ($1, $2, to_timestamp($3))`,
        [row.program_client_id, parsed.jti, parsed.exp],
      );
    } catch (err) {
      if (isJtiReplay(err)) {
        return { outcome: 'REPLAYED' };
      }
      throw err;
    }

    const issued = issueProgramToken(
      this.authConfig,
      { sub: parsed.iss, pid: row.program_id },
      this.config.tokenTtlSeconds,
    );
    return { outcome: 'OK', accessToken: issued.token, expiresAt: issued.expiresAt };
  }

  private parse(assertion: string): {
    iss: string;
    kid: string;
    jti: string;
    exp: number;
    aud: string;
    signingInput: string;
    signature: string;
  } | null {
    try {
      const parts = assertion.split('.');
      if (parts.length !== 3) {
        return null;
      }
      const [headerSegment, payloadSegment, signature] = parts as [string, string, string];
      const header = JSON.parse(
        Buffer.from(headerSegment, 'base64url').toString('utf8'),
      ) as AssertionHeader;
      // Épinglage : l'algorithme n'est jamais négocié avec le porteur.
      if (header.alg !== 'EdDSA' || typeof header.kid !== 'string') {
        return null;
      }
      const payload = JSON.parse(
        Buffer.from(payloadSegment, 'base64url').toString('utf8'),
      ) as AssertionPayload;
      if (
        typeof payload.iss !== 'string' ||
        typeof payload.aud !== 'string' ||
        typeof payload.jti !== 'string' ||
        !JTI_SHAPE.test(payload.jti) ||
        typeof payload.exp !== 'number'
      ) {
        return null;
      }
      return {
        iss: payload.iss,
        kid: header.kid,
        jti: payload.jti,
        exp: payload.exp,
        aud: payload.aud,
        signingInput: `${headerSegment}.${payloadSegment}`,
        signature,
      };
    } catch {
      return null;
    }
  }
}

function isJtiReplay(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    (err as { code?: unknown }).code === '23505' &&
    'constraint' in err &&
    (err as { constraint?: unknown }).constraint === 'uq_program_client_assertions_jti'
  );
}
