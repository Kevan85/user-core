import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  Inject,
  InternalServerErrorException,
  NotFoundException,
  ConflictException,
  Put,
  UnauthorizedException,
} from '@nestjs/common';
import { AUTH_PROVIDER, type AuthenticationProvider } from '../auth/authentication-provider';
import type { PersonCivilIdentity } from '../crypto/person-identity';
import { IDENTITY_SERVICE, type IdentityService } from './identity.service';

interface IdentityBody {
  nameComponents?: unknown;
  displayName?: unknown;
  birthDate?: unknown;
}

/**
 * L'identité d'état civil de la personne du compte. BOLA : le compte vient du
 * JETON SIGNÉ, jamais du corps ni de l'URL (patron ProfileController).
 *
 * ⚠️ C7 — le point qui a motivé la classe distincte : une violation
 * d'intégrité du registre ne devient JAMAIS un 400 « vous avez mal saisi » —
 * c'est un 500, l'incident est déjà tracé, et l'utilisateur n'y est pour rien.
 */
@Controller('account')
export class IdentityController {
  constructor(
    @Inject(IDENTITY_SERVICE) private readonly identities: IdentityService,
    @Inject(AUTH_PROVIDER) private readonly provider: AuthenticationProvider,
  ) {}

  @Get('identity')
  async get(@Headers('authorization') authorization?: string): Promise<PersonCivilIdentity> {
    const accountId = await this.requireAccount(authorization);
    const result = await this.identities.read(accountId);
    switch (result.outcome) {
      case 'OK':
        return result.identity;
      case 'NOT_PROVIDED':
        throw new NotFoundException("aucune identité civile fournie pour cette personne");
      default:
        throw new InternalServerErrorException(
          "identité momentanément indisponible — l'incident est tracé",
        );
    }
  }

  @Put('identity')
  @HttpCode(200)
  async provide(
    @Body() body: IdentityBody,
    @Headers('authorization') authorization?: string,
  ): Promise<PersonCivilIdentity> {
    const accountId = await this.requireAccount(authorization);
    const identity = readIdentityBody(body);

    const result = await this.identities.provide(accountId, identity);
    switch (result.outcome) {
      case 'OK':
        return result.identity;
      case 'INVALID':
        throw new BadRequestException(result.reason);
      default:
        throw new ConflictException(
          "l'année de naissance est posée une fois pour toutes — sa correction est un acte d'administration",
        );
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

// Façade de forme seulement : les bornes réelles (longueurs, calendrier,
// futur) vivent dans le module crypto, qui rend des messages sans PII.
function readIdentityBody(body: IdentityBody): PersonCivilIdentity {
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
