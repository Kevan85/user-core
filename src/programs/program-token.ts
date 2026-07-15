import { sign as ed25519Sign, verify as ed25519Verify } from 'crypto';
import type { AuthAssembly } from '../auth/auth-config';

/**
 * Le jeton de PROGRAMME : même trousseau Ed25519, même forme JWS compacte que
 * le jeton de compte — mais un espace de revendications STRUCTURELLEMENT
 * DISJOINT :
 *   · jeton de compte    : { sub, sid }        — sid = la session ;
 *   · jeton de programme : { sub, pid, kind }  — pid = LE programme, kind='program'.
 * Le vérificateur de comptes exige `sid` (un jeton de programme n'en a pas) ;
 * celui-ci exige `pid` ET `kind` (un jeton de compte n'a ni l'un ni l'autre).
 * Aucun jeton ne traverse la frontière — ce n'est pas une convention, c'est
 * la forme.
 *
 * LE pid EST LA SEULE SOURCE du programme pour toute l'API /v1 : jamais
 * l'URL, jamais le corps. Un programme est incapable d'interroger un autre
 * programme parce qu'il est incapable de fabriquer un jeton qui le nomme.
 */
export interface ProgramTokenClaims {
  /** L'identité cliente (client_id public, opaque). */
  sub: string;
  /** L'uuid du programme — la frontière de TOUT /v1. */
  pid: string;
}

interface ProgramTokenPayload {
  sub: string;
  pid: string;
  kind: string;
  iat: number;
  exp: number;
}

function encodeSegment(value: object): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function decodeSegment(segment: string): unknown {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
}

export function issueProgramToken(
  config: AuthAssembly,
  claims: ProgramTokenClaims,
  ttlSeconds: number,
): { token: string; expiresAt: Date } {
  const keyPair = config.keys.get(config.activeKid);
  if (keyPair === undefined) {
    throw new Error('clé de signature active introuvable (config validée au boot)');
  }
  const issuedAtSeconds = Math.floor(Date.now() / 1000);
  const expSeconds = issuedAtSeconds + ttlSeconds;
  const header = { alg: 'EdDSA', typ: 'JWT', kid: keyPair.kid };
  const payload: ProgramTokenPayload = {
    sub: claims.sub,
    pid: claims.pid,
    kind: 'program',
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

export function verifyProgramToken(config: AuthAssembly, token: string): ProgramTokenClaims | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }
    const [headerSegment, payloadSegment, signatureSegment] = parts as [string, string, string];

    const header = decodeSegment(headerSegment) as { alg?: unknown; kid?: unknown };
    // Épinglage : l'algorithme n'est jamais négocié avec le porteur.
    if (header.alg !== 'EdDSA' || typeof header.kid !== 'string') {
      return null;
    }
    const keyPair = config.keys.get(header.kid);
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

    const payload = decodeSegment(payloadSegment) as Partial<ProgramTokenPayload>;
    // LA DISJONCTION : kind='program' ET pid présents — un jeton de compte
    // (sub/sid) ne passe JAMAIS ici.
    if (
      payload.kind !== 'program' ||
      typeof payload.sub !== 'string' ||
      typeof payload.pid !== 'string' ||
      typeof payload.exp !== 'number' ||
      payload.exp * 1000 <= Date.now()
    ) {
      return null;
    }
    return { sub: payload.sub, pid: payload.pid };
  } catch {
    return null;
  }
}
