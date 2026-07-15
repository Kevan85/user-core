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
} from '@nestjs/common';
import type { Request } from 'express';
import { REGISTRATION_SERVICE, type RegistrationService } from './registration.service';

interface RegisterBody {
  secret?: unknown;
}

@Controller('auth')
export class RegistrationController {
  constructor(
    @Inject(REGISTRATION_SERVICE) private readonly registration: RegistrationService,
  ) {}

  /** L'inscription publique : l'identifiant est GÉNÉRÉ, jamais choisi. */
  @Post('register')
  @HttpCode(201)
  async register(
    @Body() body: RegisterBody,
    @Req() req: Request,
  ): Promise<{
    identifier: string;
    accessToken: string;
    accessTokenExpiresAt: string;
    refreshToken: string;
  }> {
    if (typeof body.secret !== 'string' || body.secret === '') {
      throw new BadRequestException('secret requis');
    }
    // Même règle que le login : l'adresse de la socket fait foi (V1 sans
    // proxy de confiance déclaré).
    const clientIp = req.socket.remoteAddress ?? 'unknown';

    const result = await this.registration.register(body.secret, clientIp);
    if (result.outcome === 'THROTTLED') {
      throw new HttpException('trop de tentatives, réessayer plus tard', HttpStatus.TOO_MANY_REQUESTS);
    }
    if (result.outcome === 'SECRET_TOO_SHORT') {
      throw new BadRequestException(`secret trop court (minimum ${result.minLength} caractères)`);
    }
    return {
      identifier: result.identifier,
      accessToken: result.accessToken,
      accessTokenExpiresAt: result.accessTokenExpiresAt.toISOString(),
      refreshToken: result.refreshToken,
    };
  }
}
