import {
  BadRequestException,
  Body,
  Controller,
  ForbiddenException,
  Get,
  Headers,
  HttpCode,
  HttpException,
  HttpStatus,
  Inject,
  NotFoundException,
  Param,
  Post,
  UnauthorizedException,
} from '@nestjs/common';
import { AUTH_PROVIDER, type AuthenticationProvider } from '../auth/authentication-provider';
import { CATALOG_SERVICE, type CatalogService, type ProgramView } from './catalog.service';

interface StaffGrantBody {
  accountId?: unknown;
}

@Controller('catalog')
export class CatalogController {
  constructor(
    @Inject(CATALOG_SERVICE) private readonly catalog: CatalogService,
    @Inject(AUTH_PROVIDER) private readonly provider: AuthenticationProvider,
  ) {}

  /**
   * Le catalogue du compte : activé / désactivé, et RIEN d'autre. Aucun prix,
   * aucune échéance, aucune relance — ils n'existent pas ici (§3.8).
   */
  @Get('programs')
  async list(@Headers('authorization') authorization?: string): Promise<ProgramView[]> {
    const accountId = await this.requireAccount(authorization);
    return this.catalog.list(accountId);
  }

  @Post('programs/:code/activate')
  @HttpCode(200)
  async activate(
    @Param('code') code: string,
    @Headers('authorization') authorization?: string,
  ): Promise<{ status: 'ACTIVATED' | 'ALREADY_ACTIVE' }> {
    const accountId = await this.requireAccount(authorization);
    const result = await this.catalog.activate(accountId, code);
    switch (result.outcome) {
      case 'ACTIVATED':
      case 'ALREADY_ACTIVE':
        return { status: result.outcome };
      case 'NOT_SELF_SERVICE':
        throw new ForbiddenException("ce programme s'ouvre par son responsable, pas depuis le compte");
      case 'REVOKED_BY_THIRD_PARTY':
        // La famille a été retirée par un tiers : elle ne se remet pas seule.
        throw new ForbiddenException('accès retiré par le responsable du programme');
      default:
        throw new NotFoundException('programme inconnu');
    }
  }

  /** La famille peut TOUJOURS se désactiver — c'est son compte. */
  @Post('programs/:code/deactivate')
  @HttpCode(200)
  async deactivate(
    @Param('code') code: string,
    @Headers('authorization') authorization?: string,
  ): Promise<{ status: 'DEACTIVATED' | 'NOT_ACTIVE' }> {
    const accountId = await this.requireAccount(authorization);
    const result = await this.catalog.deactivate(accountId, code);
    if (result.outcome === 'UNKNOWN_PROGRAM') {
      throw new NotFoundException('programme inconnu');
    }
    return { status: result.outcome };
  }

  /** Ouverture par le staff (mode GRANTED) : c'est le tiers qui inscrit. */
  @Post('programs/:code/grants')
  @HttpCode(201)
  async grantAsStaff(
    @Param('code') code: string,
    @Body() body: StaffGrantBody,
    @Headers('authorization') authorization?: string,
  ): Promise<{ status: 'GRANTED' | 'ALREADY_ACTIVE' }> {
    const actorId = await this.requireAccount(authorization);
    if (typeof body.accountId !== 'string' || body.accountId === '') {
      throw new BadRequestException('accountId requis');
    }
    const result = await this.catalog.grantAsStaff(actorId, body.accountId, code);
    switch (result.outcome) {
      case 'GRANTED':
      case 'ALREADY_ACTIVE':
        return { status: result.outcome };
      case 'FORBIDDEN':
        throw new HttpException('réservé au staff de la plateforme', HttpStatus.FORBIDDEN);
      default:
        throw new NotFoundException('programme ou compte inconnu');
    }
  }

  // BOLA : le compte vient du JETON SIGNÉ, jamais du corps ni de l'URL.
  private async requireAccount(authorization?: string): Promise<string> {
    const token = authorization?.startsWith('Bearer ') === true ? authorization.slice(7) : null;
    if (token === null) {
      throw new UnauthorizedException('jeton d\'accès requis');
    }
    const claims = await this.provider.verifyAccessToken(token);
    if (claims === null) {
      throw new UnauthorizedException('jeton d\'accès invalide');
    }
    return claims.sub;
  }
}
