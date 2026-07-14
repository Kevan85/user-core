import {
  BadRequestException,
  Body,
  Controller,
  ForbiddenException,
  Headers,
  HttpCode,
  HttpException,
  HttpStatus,
  Inject,
  Post,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';
import { AUTH_PROVIDER, type AuthenticationProvider } from './authentication-provider';
import { SESSION_SERVICE, type SessionService } from './session.service';

interface RefreshBody {
  refreshToken?: unknown;
}

// Refus UNIQUE côté refresh : jeton inconnu, mort, session révoquée, compte
// désactivé — même statut, même message. Le rejeu se distingue par son EFFET
// (session coupée), jamais par ce qu'on répond au porteur.
const GENERIC_REFUSAL = 'jeton de rafraîchissement invalide';

@Controller('auth')
export class SessionController {
  constructor(
    @Inject(SESSION_SERVICE) private readonly sessions: SessionService,
    @Inject(AUTH_PROVIDER) private readonly provider: AuthenticationProvider,
  ) {}

  @Post('refresh')
  @HttpCode(200)
  async refresh(
    @Body() body: RefreshBody,
    @Req() req: Request,
  ): Promise<{ accessToken: string; accessTokenExpiresAt: string; refreshToken?: string }> {
    const { refreshToken } = body;
    if (typeof refreshToken !== 'string' || refreshToken === '') {
      throw new BadRequestException('refreshToken requis');
    }
    const clientIp = req.socket.remoteAddress ?? 'unknown';

    const result = await this.sessions.refresh(refreshToken, clientIp);
    if (result.outcome === 'THROTTLED') {
      throw new HttpException('trop de tentatives, réessayer plus tard', HttpStatus.TOO_MANY_REQUESTS);
    }
    if (result.outcome !== 'OK') {
      // REPLAY_DETECTED et REFUSED : réponse identique. La session a été
      // coupée dans le cas du rejeu — le porteur n'a pas à l'apprendre ici.
      throw new UnauthorizedException(GENERIC_REFUSAL);
    }
    return {
      accessToken: result.accessToken,
      accessTokenExpiresAt: result.accessTokenExpiresAt.toISOString(),
      ...(result.refreshToken === undefined ? {} : { refreshToken: result.refreshToken }),
    };
  }

  @Post('logout')
  @HttpCode(200)
  async logout(@Headers('authorization') authorization?: string): Promise<{ revokedSessions: number }> {
    const claims = await this.requireClaims(authorization);
    // BOLA : le compte et la session viennent du JETON SIGNÉ, jamais du
    // corps de la requête — un compte ne peut pas nommer la session d'un
    // autre. Le service re-filtre sur account_id (ceinture).
    const result = await this.sessions.logout(claims.sub, claims.sid);
    if (result.outcome !== 'OK') {
      throw new ForbiddenException('session introuvable ou déjà révoquée');
    }
    return { revokedSessions: result.revokedSessions };
  }

  @Post('sessions/revoke-all')
  @HttpCode(200)
  async revokeAll(
    @Headers('authorization') authorization?: string,
  ): Promise<{ revokedSessions: number }> {
    const claims = await this.requireClaims(authorization);
    const result = await this.sessions.revokeAll(claims.sub);
    if (result.outcome !== 'OK') {
      throw new ForbiddenException('révocation impossible');
    }
    return { revokedSessions: result.revokedSessions };
  }

  private async requireClaims(authorization?: string): Promise<{ sub: string; sid: string }> {
    const token = authorization?.startsWith('Bearer ') === true ? authorization.slice(7) : null;
    if (token === null) {
      throw new UnauthorizedException('jeton d\'accès requis');
    }
    const claims = await this.provider.verifyAccessToken(token);
    if (claims === null) {
      throw new UnauthorizedException('jeton d\'accès invalide');
    }
    return claims;
  }
}
