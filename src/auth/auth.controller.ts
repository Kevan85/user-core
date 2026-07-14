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
  constructor(@Inject(AUTH_SERVICE) private readonly auth: AuthService) {}

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
    // V1 sans proxy de confiance déclaré : l'adresse de la socket fait foi.
    // Le jour d'un reverse proxy, le patron payment-core (liste d'IP de
    // confiance en config) s'applique — jamais un x-forwarded-for cru.
    const clientIp = req.socket.remoteAddress ?? 'unknown';

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
