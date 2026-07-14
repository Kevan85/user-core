/**
 * AuthenticationProvider — LA couture réversible n°1 (CLAUDE.md §3.9, CDC D2).
 * Le maison (LocalAuthenticationProvider) vit derrière ; une brique du marché
 * se branche ici le jour où la surface « ennuyeuse » l'exige — sans réécrire
 * un seul consommateur. Le cœur ne parle que ce vocabulaire.
 *
 * Claims du jeton d'accès : sub = uuid du compte, sid = uuid de session.
 * JAMAIS le public_identifier — c'est un identifiant de CONNEXION, pas un
 * identifiant technique (tranché Q2). Zéro PII dans un jeton.
 */
export interface AccessTokenClaims {
  sub: string;
  sid: string;
}

export interface IssuedAccessToken {
  token: string;
  expiresAt: Date;
}

export interface AuthenticationProvider {
  hashSecret(plain: string): Promise<string>;
  /** Rend false sur échec OU sur hash illisible — jamais d'exception. */
  verifySecret(encodedHash: string, plain: string): Promise<boolean>;
  issueAccessToken(claims: AccessTokenClaims): Promise<IssuedAccessToken>;
  /** Rend null sur signature invalide, kid inconnu, forme inattendue. */
  verifyAccessToken(token: string): Promise<AccessTokenClaims | null>;
}

export const AUTH_SERVICE = 'AUTH_SERVICE';
export const AUTH_PROVIDER = 'AUTH_PROVIDER';
