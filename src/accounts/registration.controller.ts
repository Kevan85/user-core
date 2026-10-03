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
import { CLIENT_ADDRESS, type ClientAddress } from '../client-address/client-address';
import { REGISTRATION_SERVICE, type RegistrationService } from './registration.service';

interface RegisterBody {
  secret?: unknown;
}

@Controller('auth')
export class RegistrationController {
  constructor(
    @Inject(REGISTRATION_SERVICE) private readonly registration: RegistrationService,
    @Inject(CLIENT_ADDRESS) private readonly clientAddress: ClientAddress,
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
    // L'adresse cliente vient du point unique : derrière un aiguilleur DÉCLARÉ,
    // celle qu'il a vue ; sinon la socket (src/client-address/client-address.ts).
    const clientIp = this.clientAddress.of(req, 'PUBLIC');

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
