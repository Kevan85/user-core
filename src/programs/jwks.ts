import type { AuthAssembly } from '../auth/auth-config';

/**
 * JWKS (LOT 4, étape 6) : les clés PUBLIQUES de signature des jetons — le
 * premier vérificateur externe existe (les programmes), la publication se
 * justifie donc MAINTENANT, pas « au cas où ».
 *
 * FORME CLOSE, construite champ par champ : jamais un export brut d'objet.
 * Node exporte un JWK Ed25519 public sous la forme { kty, crv, x } — la
 * composante privée (d) n'existe que si l'on exporte la clé PRIVÉE, ce que
 * ce fichier ne touche jamais (publicKey seulement). Le test le prouve par
 * Object.keys sur chaque clé rendue.
 */
export const PROGRAM_JWKS = 'PROGRAM_JWKS';

export interface PublicJwk {
  kty: 'OKP';
  crv: 'Ed25519';
  kid: string;
  x: string;
  use: 'sig';
  alg: 'EdDSA';
}

export function buildJwks(config: AuthAssembly): { keys: PublicJwk[] } {
  const keys: PublicJwk[] = [];
  for (const [kid, pair] of config.keys) {
    const exported = pair.publicKey.export({ format: 'jwk' }) as {
      kty?: unknown;
      crv?: unknown;
      x?: unknown;
    };
    if (exported.kty !== 'OKP' || exported.crv !== 'Ed25519' || typeof exported.x !== 'string') {
      throw new Error(`JWKS : la clé « ${kid} » n'est pas une Ed25519 publique exportable`);
    }
    keys.push({ kty: 'OKP', crv: 'Ed25519', kid, x: exported.x, use: 'sig', alg: 'EdDSA' });
  }
  return { keys };
}
