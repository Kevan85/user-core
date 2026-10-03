import {
  BadRequestException,
  Body,
  Controller,
  HttpCode,
  HttpException,
  HttpStatus,
  Inject,
  Post,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';
import { CLIENT_ADDRESS, type ClientAddress } from '../client-address/client-address';
import { AUTH_SERVICE } from './authentication-provider';
import type { AuthService } from './auth.service';

interface LoginBody {
  identifier?: unknown;
  secret?: unknown;
}

// Réponse d'échec UNIQUE : compte inconnu, désactivé, verrouillé, secret
// expiré ou faux — même statut, même message. Le chrono est égalisé par le
// service (C3) ; le message l'est ici.
const GENERIC_FAILURE = 'identifiants invalides';

@Controller('auth')
export class AuthController {
  constructor(
    @Inject(AUTH_SERVICE) private readonly auth: AuthService,
    @Inject(CLIENT_ADDRESS) private readonly clientAddress: ClientAddress,
  ) {}

  @Post('login')
  @HttpCode(200)
  async login(
    @Body() body: LoginBody,
    @Req() req: Request,
  ): Promise<{
    accessToken: string;
    accessTokenExpiresAt: string;
    refreshToken: string;
    mustChangeSecret: boolean;
  }> {
    const { identifier, secret } = body;
    if (typeof identifier !== 'string' || identifier === '' || typeof secret !== 'string' || secret === '') {
      throw new BadRequestException('identifier et secret sont requis');
    }
    // L'adresse cliente vient du point unique : derrière un aiguilleur DÉCLARÉ
    // dans USER_CORE_TRUSTED_PROXIES, celle qu'il a vue ; sinon la socket. Un
    // en-tête X-Forwarded-For venu d'ailleurs n'est jamais cru — et ce n'est plus
    // une promesse de commentaire : le mur, sa référence et ses tests vivent dans
    // src/client-address/client-address.ts.
    const clientIp = this.clientAddress.of(req, 'PUBLIC');

    const result = await this.auth.login(identifier, secret, clientIp);
    if (result.outcome === 'THROTTLED') {
      throw new HttpException('trop de tentatives, réessayer plus tard', HttpStatus.TOO_MANY_REQUESTS);
    }
    if (result.outcome === 'FAILED') {
      throw new UnauthorizedException(GENERIC_FAILURE);
    }
    return {
      accessToken: result.accessToken,
      accessTokenExpiresAt: result.accessTokenExpiresAt.toISOString(),
      refreshToken: result.refreshToken,
      mustChangeSecret: result.mustChangeSecret,
    };
  }
}
