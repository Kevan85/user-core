import {
  BadRequestException,
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  Inject,
  Put,
  UnauthorizedException,
  Headers,
} from '@nestjs/common';
import { AUTH_PROVIDER, type AuthenticationProvider } from '../auth/authentication-provider';
import { PROFILE_SERVICE, type ProfileService, type ProfileView } from './profile.service';

interface ProfileBody {
  displayName?: unknown;
  locale?: unknown;
}

@Controller('account')
export class ProfileController {
  constructor(
    @Inject(PROFILE_SERVICE) private readonly profiles: ProfileService,
    @Inject(AUTH_PROVIDER) private readonly provider: AuthenticationProvider,
  ) {}

  @Get('profile')
  async get(@Headers('authorization') authorization?: string): Promise<ProfileView> {
    const accountId = await this.requireAccount(authorization);
    return this.profiles.get(accountId);
  }

  /** PUT : la requête REMPLACE le profil (un champ absent l'efface). */
  @Put('profile')
  @HttpCode(200)
  async replace(
    @Body() body: ProfileBody,
    @Headers('authorization') authorization?: string,
  ): Promise<ProfileView> {
    const accountId = await this.requireAccount(authorization);
    const displayName = readOptionalString(body.displayName, 'displayName');
    const locale = readOptionalString(body.locale, 'locale');

    const result = await this.profiles.replace(accountId, { displayName, locale });
    switch (result.outcome) {
      case 'OK':
        return result.profile;
      case 'INVALID_DISPLAY_NAME':
        throw new BadRequestException('displayName : 1 à 80 caractères');
      case 'INVALID_LOCALE':
        throw new BadRequestException('locale : forme « fr » ou « fr-CD » attendue');
      default:
        throw new ForbiddenException('compte inactif');
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

function readOptionalString(value: unknown, name: string): string | null {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== 'string') {
    throw new BadRequestException(`${name} : chaîne attendue`);
  }
  return value;
}
