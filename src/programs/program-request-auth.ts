import type { AuthAssembly } from '../auth/auth-config';
import type { LoginThrottle } from '../auth/login-throttle';
import { verifyProgramToken } from './program-token';

/**
 * LE MUR D'APPEL de l'API métier /v1 (étape 1 du lot) : toute opération
 * qu'un programme demande passe ICI avant de toucher un service.
 *
 * BOLA DE PROGRAMME — la règle qui commande tout : le programme agissant est
 * `programId`, résolu du JETON SIGNÉ, et de lui seul. Jamais l'URL, jamais le
 * corps, jamais un en-tête libre. Un programme est incapable d'agir au nom
 * d'un autre parce qu'il est incapable de fabriquer un jeton qui le nomme
 * (la disjonction structurelle des jetons vit dans program-token.ts : un
 * jeton de COMPTE n'a ni pid ni kind, il est nul ici par la forme).
 *
 * Le throttle est PAR CLIENT authentifié (budget dédié, distinct de celui de
 * /v1/token) : il borne le débit métier d'un client bavard sans offrir de
 * levier global. Un porteur NON authentifié n'y touche pas — un refus 401 ne
 * consomme aucun budget attribuable, et un plafond partagé entre inconnus
 * serait un déni de service offert à n'importe qui (même arbitrage que
 * l'inscription publique, LOT 4).
 *
 * Patron du dépôt : ce module rend des VERDICTS ; les contrôleurs (étapes
 * 3-5) les traduisent en HTTP. Aucune exception NestJS ici.
 */
export interface ProgramCaller {
  /** L'identité cliente authentifiée (client_id public). */
  clientId: string;
  /** LE programme au nom duquel tout /v1 agit — la frontière BOLA. */
  programId: string;
}

export type ProgramRequestResult =
  | { outcome: 'OK'; caller: ProgramCaller }
  /** Absent, difforme, signature fausse, périmé, jeton de compte : un seul refus. */
  | { outcome: 'UNAUTHORIZED' }
  | { outcome: 'THROTTLED' };

export const PROGRAM_REQUEST_AUTH = 'PROGRAM_REQUEST_AUTH';

export class ProgramRequestAuth {
  constructor(
    private readonly authConfig: AuthAssembly,
    private readonly throttle: LoginThrottle,
  ) {}

  authenticate(authorization: string | undefined): ProgramRequestResult {
    const token =
      authorization?.startsWith('Bearer ') === true ? authorization.slice(7) : null;
    if (token === null) {
      return { outcome: 'UNAUTHORIZED' };
    }
    const claims = verifyProgramToken(this.authConfig, token);
    if (claims === null) {
      return { outcome: 'UNAUTHORIZED' };
    }
    // Le budget se compte APRÈS authentification, sur l'identité cliente : la
    // clé est prouvée par signature, elle ne se falsifie pas pour épuiser le
    // budget d'un tiers.
    if (!this.throttle.allowByKey(claims.sub)) {
      return { outcome: 'THROTTLED' };
    }
    return { outcome: 'OK', caller: { clientId: claims.sub, programId: claims.pid } };
  }
}
