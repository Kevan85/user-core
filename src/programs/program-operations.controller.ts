import {
  BadRequestException,
  Body,
  Controller,
  ConflictException,
  ForbiddenException,
  Headers,
  HttpCode,
  HttpException,
  HttpStatus,
  Inject,
  NotFoundException,
  Post,
  UnauthorizedException,
} from '@nestjs/common';
import type { PersonCivilIdentity } from '../crypto/person-identity';
import {
  DEPENDENT_ACCESS_SERVICE,
  type DependentAccessService,
} from './dependent-access.service';
import {
  PROGRAM_GRANTS_SERVICE,
  type ProgramGrantsService,
} from './program-grants.service';
import {
  PROGRAM_REQUEST_AUTH,
  type ProgramCaller,
  type ProgramRequestAuth,
} from './program-request-auth';

interface DependentAccessBody {
  reference?: unknown;
  dependent?: { nameComponents?: unknown; displayName?: unknown; birthDate?: unknown };
  responsiblePhone?: unknown;
}

interface KnownPersonGrantBody {
  personIdentifier?: unknown;
}

const MAX_REFERENCE_LENGTH = 128;

/**
 * Les opérations métier /v1 (étape 3). Le MUR d'abord (étape 1) : le
 * programme vient du jeton signé — jamais de l'URL, jamais du corps.
 *
 * ⚠️ AUCUN log dans ce fichier ni dans les services : le payload porte une
 * identité en clair, un numéro en clair et une référence qui peut porter de
 * la PII (§3.2).
 */
@Controller('v1')
export class ProgramOperationsController {
  constructor(
    @Inject(PROGRAM_REQUEST_AUTH) private readonly wall: ProgramRequestAuth,
    @Inject(DEPENDENT_ACCESS_SERVICE) private readonly dependents: DependentAccessService,
    @Inject(PROGRAM_GRANTS_SERVICE) private readonly grants: ProgramGrantsService,
  ) {}

  /**
   * LE CLIC — nouvelle famille : l'ayant droit naît avec son droit, le
   * responsable est invité par sa ligne. Réservé aux MINEURS (le verdict
   * OF_AGE oriente vers /v1/grants). Accusé UNIFORME : numéro connu ou non,
   * invitation vive ou silencieuse — la même réponse.
   */
  @Post('dependent-access')
  @HttpCode(201)
  async openDependentAccess(
    @Body() body: DependentAccessBody,
    @Headers('authorization') authorization?: string,
  ): Promise<{ dependentIdentifier: string }> {
    const caller = this.requireProgram(authorization);
    const reference = readReference(body.reference);
    const dependent = readIdentityBody(body.dependent);
    if (typeof body.responsiblePhone !== 'string') {
      throw new BadRequestException('responsiblePhone : chaîne attendue');
    }

    const result = await this.dependents.open(
      caller.programId,
      reference,
      dependent,
      body.responsiblePhone,
    );
    switch (result.outcome) {
      case 'ACCEPTED':
        return { dependentIdentifier: result.dependentIdentifier };
      case 'OF_AGE':
        throw new ConflictException(
          'personne majeure au sens du seuil : ce chemin est celui des ayants droit mineurs — ' +
            "utiliser l'ouverture de droit sur personne connue (POST /v1/grants)",
        );
      case 'NOT_GRANTED_MODE':
        throw new ConflictException(
          "programme en libre-service : l'ouverture par un tiers n'existe pas — la famille active elle-même",
        );
      case 'THROTTLED':
        throw new HttpException(
          "plafond d'invitations du client atteint, réessayer plus tard",
          HttpStatus.TOO_MANY_REQUESTS,
        );
      case 'INVALID_PHONE':
        throw new BadRequestException('responsiblePhone : forme de numéro invalide');
      case 'INVALID_IDENTITY':
        throw new BadRequestException(result.reason);
      default:
        throw new ForbiddenException('programme inconnu ou retiré du catalogue');
    }
  }

  /**
   * L'OUVERTURE SUR PERSONNE CONNUE : le droit, rien que le droit — pour
   * l'identifiant public que la personne (ou son responsable) a DONNÉ au
   * programme, ou que le clic lui a rendu.
   */
  @Post('grants')
  @HttpCode(201)
  async openKnownPersonGrant(
    @Body() body: KnownPersonGrantBody,
    @Headers('authorization') authorization?: string,
  ): Promise<{ status: 'GRANTED' | 'ALREADY_ACTIVE' }> {
    const caller = this.requireProgram(authorization);
    const identifier = readPersonIdentifier(body.personIdentifier);

    const result = await this.grants.openForKnownPerson(caller.programId, identifier);
    switch (result.outcome) {
      case 'GRANTED':
        return { status: 'GRANTED' };
      case 'ALREADY_ACTIVE':
        return { status: 'ALREADY_ACTIVE' };
      case 'CLOSED_BY_FAMILY':
        throw new ConflictException(
          'la famille a fermé ce programme — elle seule le rouvre',
        );
      case 'NOT_GRANTED_MODE':
        throw new ConflictException(
          "programme en libre-service : l'ouverture par un tiers n'existe pas",
        );
      case 'NOT_FOUND':
        throw new NotFoundException('personne inconnue');
      default:
        throw new ForbiddenException('programme inconnu ou retiré du catalogue');
    }
  }

  /**
   * LA LECTURE (étape 4) : le droit de CE programme pour cette personne —
   * jamais ceux d'un autre (frontière §7). POST et corps, pas GET et URL :
   * un identifiant de personne n'entre jamais dans un chemin ou une query
   * (les access-logs des proxys journalisent les URL — §3.2 par construction).
   */
  @Post('grants/status')
  @HttpCode(200)
  async knownPersonGrantStatus(
    @Body() body: KnownPersonGrantBody,
    @Headers('authorization') authorization?: string,
  ): Promise<{ status: 'ACTIVE' | 'REVOKED' | 'NONE'; grantedAt?: string; revokedAt?: string }> {
    const caller = this.requireProgram(authorization);
    const identifier = readPersonIdentifier(body.personIdentifier);
    const result = await this.grants.statusForKnownPerson(caller.programId, identifier);
    if (result.outcome === 'NOT_FOUND') {
      throw new NotFoundException('personne inconnue');
    }
    return { status: result.status, grantedAt: result.grantedAt, revokedAt: result.revokedAt };
  }

  /**
   * LA RÉVOCATION par le programme : son droit, motif PROGRAM — la matrice
   * de 019 fait le reste (la famille ne rouvre pas ce qu'un tiers a fermé ;
   * le programme, si). Un re-revoke rend NOT_ACTIVE en 200 : un constat
   * idempotent, pas une erreur.
   */
  @Post('grants/revoke')
  @HttpCode(200)
  async revokeKnownPersonGrant(
    @Body() body: KnownPersonGrantBody,
    @Headers('authorization') authorization?: string,
  ): Promise<{ status: 'REVOKED' | 'NOT_ACTIVE' }> {
    const caller = this.requireProgram(authorization);
    const identifier = readPersonIdentifier(body.personIdentifier);
    const result = await this.grants.revokeForKnownPerson(caller.programId, identifier);
    if (result.outcome === 'NOT_FOUND') {
      throw new NotFoundException('personne inconnue');
    }
    return { status: result.outcome };
  }

  // Le mur de l'étape 1, traduit en HTTP — un seul point, pour tous les
  // endpoints métier de ce contrôleur.
  private requireProgram(authorization?: string): ProgramCaller {
    const result = this.wall.authenticate(authorization);
    if (result.outcome === 'THROTTLED') {
      throw new HttpException('trop de requêtes, réessayer plus tard', HttpStatus.TOO_MANY_REQUESTS);
    }
    if (result.outcome !== 'OK') {
      throw new UnauthorizedException('jeton de programme requis');
    }
    return result.caller;
  }
}

function readPersonIdentifier(value: unknown): string {
  if (typeof value !== 'string' || !/^[1-9][0-9]{9}$/.test(value)) {
    throw new BadRequestException('personIdentifier : 10 chiffres attendus');
  }
  return value;
}

function readReference(value: unknown): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > MAX_REFERENCE_LENGTH) {
    throw new BadRequestException(
      `reference : chaîne de 1 à ${MAX_REFERENCE_LENGTH} caractères attendue`,
    );
  }
  return value;
}

// Façade de forme (patron IdentityController) : les bornes réelles vivent
// dans le module crypto, qui rend des messages sans PII.
function readIdentityBody(body: DependentAccessBody['dependent']): PersonCivilIdentity {
  if (body === undefined || body === null || typeof body !== 'object') {
    throw new BadRequestException('dependent : objet attendu');
  }
  if (!Array.isArray(body.nameComponents) || body.nameComponents.some((c) => typeof c !== 'string')) {
    throw new BadRequestException('dependent.nameComponents : tableau de chaînes attendu');
  }
  if (typeof body.displayName !== 'string') {
    throw new BadRequestException('dependent.displayName : chaîne attendue');
  }
  if (typeof body.birthDate !== 'string') {
    throw new BadRequestException('dependent.birthDate : chaîne attendue');
  }
  return {
    nameComponents: body.nameComponents as string[],
    displayName: body.displayName,
    birthDate: body.birthDate,
  };
}
