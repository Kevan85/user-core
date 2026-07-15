import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpException,
  HttpStatus,
  Inject,
  Post,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';
import { PROGRAM_JWKS, type PublicJwk } from './jwks';
import { PROGRAM_AUTH_SERVICE, type ProgramAuthService } from './program-auth.service';

interface TokenBody {
  assertion?: unknown;
}

// Refus UNIQUE : client inconnu, clé révoquée, signature fausse, assertion
// périmée ou REJOUÉE — même statut, même message. Rien ne s'énumère.
const GENERIC_FAILURE = 'assertion invalide';

@Controller('v1')
export class ProgramAuthController {
  constructor(
    @Inject(PROGRAM_AUTH_SERVICE) private readonly programAuth: ProgramAuthService,
    @Inject(PROGRAM_JWKS) private readonly jwks: { keys: PublicJwk[] },
  ) {}

  /** L'échange assertion signée → jeton court de programme. */
  @Post('token')
  @HttpCode(200)
  async token(
    @Body() body: TokenBody,
    @Req() req: Request,
  ): Promise<{ accessToken: string; expiresAt: string }> {
    if (typeof body.assertion !== 'string' || body.assertion === '') {
      throw new UnauthorizedException(GENERIC_FAILURE);
    }
    const clientIp = req.socket.remoteAddress ?? 'unknown';
    const result = await this.programAuth.token(body.assertion, clientIp);
    if (result.outcome === 'THROTTLED') {
      throw new HttpException('trop de tentatives, réessayer plus tard', HttpStatus.TOO_MANY_REQUESTS);
    }
    if (result.outcome !== 'OK') {
      // REFUSED et REPLAYED : indiscernables du dehors, à dessein.
      throw new UnauthorizedException(GENERIC_FAILURE);
    }
    return { accessToken: result.accessToken, expiresAt: result.expiresAt.toISOString() };
  }

  /**
   * Les clés PUBLIQUES de vérification — publiques par nature, donc sans
   * authentification. Construit UNE FOIS au boot (les clés ne changent pas
   * sans redémarrage) ; forme close prouvée par test.
   */
  @Get('jwks')
  getJwks(): { keys: PublicJwk[] } {
    return this.jwks;
  }
}
