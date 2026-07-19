import {
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  ForbiddenException,
  Headers,
  HttpCode,
  Inject,
  NotFoundException,
  Param,
  Post,
  UnauthorizedException,
} from '@nestjs/common';
import { AUTH_PROVIDER, type AuthenticationProvider } from '../auth/authentication-provider';
import type { PersonCivilIdentity } from '../crypto/person-identity';
import {
  RESPONSIBILITIES_SERVICE,
  type ResponsibilitiesService,
} from './responsibilities.service';

interface AttachBody {
  nameComponents?: unknown;
  displayName?: unknown;
  birthDate?: unknown;
}

interface CoResponsibleBody {
  personPublicIdentifier?: unknown;
}

interface EndBody {
  replacementPersonPublicIdentifier?: unknown;
}

/**
 * Le lien de responsabilité. BOLA : le compte agissant vient du JETON SIGNÉ.
 * Retirer un responsable vit sous /staff : acte contrôlé (rôle vérifié en
 * service), tracé par le registre — jamais un self-service.
 */
@Controller()
export class ResponsibilitiesController {
  constructor(
    @Inject(RESPONSIBILITIES_SERVICE) private readonly responsibilities: ResponsibilitiesService,
    @Inject(AUTH_PROVIDER) private readonly provider: AuthenticationProvider,
  ) {}

  @Post('account/dependents')
  @HttpCode(201)
  async attach(
    @Body() body: AttachBody,
    @Headers('authorization') authorization?: string,
  ): Promise<{
    dependentPersonId: string;
    dependentPublicIdentifier: string;
    responsibilityId: string;
  }> {
    const accountId = await this.requireAccount(authorization);
    const identity = readIdentityBody(body);

    const result = await this.responsibilities.attach(accountId, identity);
    switch (result.outcome) {
      case 'OK':
        return {
          dependentPersonId: result.dependentPersonId,
          dependentPublicIdentifier: result.dependentPublicIdentifier,
          responsibilityId: result.responsibilityId,
        };
      case 'INVALID_IDENTITY':
        throw new BadRequestException(result.reason);
      case 'DEPENDENT_NOT_MINOR':
        throw new ConflictException(
          'cette personne est majeure au sens du seuil : un adulte n’a pas de responsable',
        );
      default:
        throw new ForbiddenException('compte inactif');
    }
  }

  @Post('account/dependents/:dependentPersonId/responsibles')
  @HttpCode(201)
  async addCoResponsible(
    @Param('dependentPersonId') dependentPersonId: string,
    @Body() body: CoResponsibleBody,
    @Headers('authorization') authorization?: string,
  ): Promise<{ responsibilityId: string }> {
    const accountId = await this.requireAccount(authorization);
    if (typeof body.personPublicIdentifier !== 'string') {
      throw new BadRequestException('personPublicIdentifier : chaîne attendue');
    }

    const result = await this.responsibilities.addCoResponsible(
      accountId,
      dependentPersonId,
      body.personPublicIdentifier,
    );
    switch (result.outcome) {
      case 'OK':
        return { responsibilityId: result.responsibilityId };
      case 'NOT_RESPONSIBLE':
        // BOLA : on ne confirme pas l'existence d'une personne qu'on ne gère pas.
        throw new NotFoundException('personne inconnue de ce compte');
      case 'UNKNOWN_PERSON':
        throw new NotFoundException('personne inconnue');
      case 'CO_RESPONSIBLE_CANNOT_ACT':
        throw new ConflictException('le co-responsable n’a aucun compte actif');
      case 'PERSON_IS_AUTONOMOUS':
        throw new ConflictException('cette personne est autonome : elle n’a pas de responsable');
      default:
        throw new ConflictException('ce responsable est déjà en place');
    }
  }

  @Post('staff/responsibilities/:responsibilityId/end')
  @HttpCode(200)
  async end(
    @Param('responsibilityId') responsibilityId: string,
    @Body() body: EndBody,
    @Headers('authorization') authorization?: string,
  ): Promise<{ ended: true }> {
    const accountId = await this.requireAccount(authorization);
    const replacement =
      body.replacementPersonPublicIdentifier === undefined ||
      body.replacementPersonPublicIdentifier === null
        ? null
        : String(body.replacementPersonPublicIdentifier);

    const result = await this.responsibilities.endResponsibility(
      accountId,
      responsibilityId,
      replacement,
    );
    switch (result.outcome) {
      case 'OK':
        return { ended: true };
      case 'FORBIDDEN':
        throw new ForbiddenException('acte réservé au staff de la plateforme');
      case 'UNKNOWN_RESPONSIBILITY':
        throw new NotFoundException('lien inconnu ou déjà clos');
      case 'UNKNOWN_PERSON':
        throw new NotFoundException('personne de remplacement inconnue');
      case 'WOULD_ORPHAN':
        throw new ConflictException(
          'dernier responsable actif : fournir un remplaçant dans le même acte',
        );
      default:
        throw new ConflictException('le remplaçant n’a aucun compte actif');
    }
  }

  // BOLA : le compte vient du JETON SIGNÉ, jamais du corps ni de l'URL.
  private async requireAccount(authorization?: string): Promise<string> {
    const token = authorization?.startsWith('Bearer ') === true ? authorization.slice(7) : null;
    if (token === null) {
      throw new UnauthorizedException("jeton d'accès requis");
    }
    const claims = await this.provider.verifyAccessToken(token);
    if (claims === null) {
      throw new UnauthorizedException("jeton d'accès invalide");
    }
    return claims.sub;
  }
}

function readIdentityBody(body: AttachBody): PersonCivilIdentity {
  if (
    !Array.isArray(body.nameComponents) ||
    body.nameComponents.some((c) => typeof c !== 'string')
  ) {
    throw new BadRequestException('nameComponents : tableau de chaînes attendu');
  }
  if (typeof body.displayName !== 'string') {
    throw new BadRequestException('displayName : chaîne attendue');
  }
  if (typeof body.birthDate !== 'string') {
    throw new BadRequestException('birthDate : chaîne attendue');
  }
  return {
    nameComponents: body.nameComponents as string[],
    displayName: body.displayName,
    birthDate: body.birthDate,
  };
}
