import { randomBytes, sign as ed25519Sign, verify as ed25519Verify } from 'crypto';
import * as argon2 from 'argon2';
import type { AuthAssembly } from './auth-config';
import type {
  AccessTokenClaims,
  AuthenticationProvider,
  IssuedAccessToken,
} from './authentication-provider';

/**
 * Le « maison » derrière la couture : argon2id (bibliothèque éprouvée) +
 * jetons d'accès JWS compact EdDSA/Ed25519 via les primitives du runtime
 * Node (crypto.sign/verify — le patron des reçus signés de payment-core),
 * kid dans l'en-tête dès le premier jeton.
 *
 * Pourquoi pas une lib JWT : jose est ESM-only (incompatible harnais CJS) et
 * jsonwebtoken ne supporte pas EdDSA — contrainte documentée (tranché Q2).
 * L'assemblage JWS est de l'ENCODAGE ; la cryptographie reste celle du
 * runtime. La vérification ÉPINGLE l'algorithme : un jeton qui annonce autre
 * chose qu'EdDSA est rejeté avant toute signature.
 */
interface TokenHeader {
  alg: string;
  typ: string;
  kid: string;
}

interface TokenPayload {
  sub: string;
  sid: string;
  iat: number;
  exp: number;
}

function encodeSegment(value: object): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function decodeSegment(segment: string): unknown {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
}

export class LocalAuthenticationProvider implements AuthenticationProvider {
  // C3 : hash de référence, calculé à l'init avec les MÊMES paramètres que
  // les vrais — le chemin « compte inconnu / secret caché » paie exactement
  // un argon2, comme le chemin « mauvais secret ». L'oracle de chrono meurt.
  private referenceHash: string | null = null;

  constructor(private readonly config: AuthAssembly) {}

  async init(): Promise<void> {
    this.referenceHash = await this.hashSecret(randomBytes(32).toString('hex'));
  }

  getReferenceHash(): string {
    if (this.referenceHash === null) {
      throw new Error('LocalAuthenticationProvider : init() n\'a pas été appelé');
    }
    return this.referenceHash;
  }

  async hashSecret(plain: string): Promise<string> {
    // Forme encodée : le hash PORTE ses paramètres (C7) — argon2.verify les
    // relit depuis la chaîne, jamais depuis la config du moment.
    return argon2.hash(plain, {
      type: argon2.argon2id,
      memoryCost: this.config.argon2.memoryCost,
      timeCost: this.config.argon2.timeCost,
      parallelism: this.config.argon2.parallelism,
    });
  }

  async verifySecret(encodedHash: string, plain: string): Promise<boolean> {
    try {
      return await argon2.verify(encodedHash, plain);
    } catch {
      // Hash illisible = échec de vérification, jamais une exception qui
      // distinguerait ce chemin des autres.
      return false;
    }
  }

  async issueAccessToken(claims: AccessTokenClaims): Promise<IssuedAccessToken> {
    const keyPair = this.config.keys.get(this.config.activeKid);
    if (keyPair === undefined) {
      throw new Error('clé de signature active introuvable (config validée au boot)');
    }
    const issuedAtSeconds = Math.floor(Date.now() / 1000);
    const expSeconds = issuedAtSeconds + this.config.accessTokenTtlSeconds;
    const header: TokenHeader = { alg: 'EdDSA', typ: 'JWT', kid: keyPair.kid };
    const payload: TokenPayload = {
      sub: claims.sub,
      sid: claims.sid,
      iat: issuedAtSeconds,
      exp: expSeconds,
    };
    const signingInput = `${encodeSegment(header)}.${encodeSegment(payload)}`;
    const signature = ed25519Sign(null, Buffer.from(signingInput, 'utf8'), keyPair.privateKey);
    return {
      token: `${signingInput}.${signature.toString('base64url')}`,
      expiresAt: new Date(expSeconds * 1000),
    };
  }

  async verifyAccessToken(token: string): Promise<AccessTokenClaims | null> {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return null;
      }
      const [headerSegment, payloadSegment, signatureSegment] = parts as [string, string, string];

      const header = decodeSegment(headerSegment) as Partial<TokenHeader>;
      // Épinglage : l'algorithme n'est jamais négocié avec le porteur.
      if (header.alg !== 'EdDSA' || typeof header.kid !== 'string') {
        return null;
      }
      const keyPair = this.config.keys.get(header.kid);
      if (keyPair === undefined) {
        return null;
      }

      const authentic = ed25519Verify(
        null,
        Buffer.from(`${headerSegment}.${payloadSegment}`, 'utf8'),
        keyPair.publicKey,
        Buffer.from(signatureSegment, 'base64url'),
      );
      if (!authentic) {
        return null;
      }

      const payload = decodeSegment(payloadSegment) as Partial<TokenPayload>;
      if (
        typeof payload.sub !== 'string' ||
        typeof payload.sid !== 'string' ||
        typeof payload.exp !== 'number' ||
        payload.exp * 1000 <= Date.now()
      ) {
        return null;
      }
      return { sub: payload.sub, sid: payload.sid };
    } catch {
      return null;
    }
  }
}
