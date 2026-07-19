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
import { EMANCIPATION_SERVICE, type EmancipationService } from './emancipation.service';

interface StartBody {
  personPublicIdentifier?: unknown;
  phone?: unknown;
  channel?: unknown;
}

interface CompleteBody {
  personPublicIdentifier?: unknown;
  code?: unknown;
  secret?: unknown;
}

/**
 * L'émancipation — endpoints PUBLICS (le demandeur n'a pas encore de compte),
 * throttlés par IP, SANS ORACLE : l'existence d'une personne ne se sonde pas.
 * Toute ouverture rend le même accusé ; tout échec d'achèvement rend le même
 * refus. Les murs (âge, ligne prouvée, coupure) vivent en base (020).
 */
@Controller('emancipation')
export class EmancipationController {
  constructor(
    @Inject(EMANCIPATION_SERVICE) private readonly emancipation: EmancipationService,
  ) {}

  @Post('start')
  @HttpCode(202)
  async start(@Body() body: StartBody, @Req() req: Request): Promise<{ accepted: true }> {
    const personPublicIdentifier = requireString(body.personPublicIdentifier, 'personPublicIdentifier');
    const phone = requireString(body.phone, 'phone');
    const channel = body.channel === 'CALL' ? 'CALL' : 'SMS';
    const clientIp = req.socket.remoteAddress ?? 'unknown';

    const result = await this.emancipation.start(personPublicIdentifier, phone, channel, clientIp);
    if (result.outcome === 'THROTTLED') {
      throw new HttpException('trop de tentatives, réessayer plus tard', HttpStatus.TOO_MANY_REQUESTS);
    }
    return { accepted: true };
  }

  @Post('complete')
  @HttpCode(200)
  async complete(
    @Body() body: CompleteBody,
    @Req() req: Request,
  ): Promise<{ accountIdentifier: string }> {
    const personPublicIdentifier = requireString(body.personPublicIdentifier, 'personPublicIdentifier');
    const code = requireString(body.code, 'code');
    const secret = requireString(body.secret, 'secret');
    const clientIp = req.socket.remoteAddress ?? 'unknown';

    const result = await this.emancipation.complete(personPublicIdentifier, code, secret, clientIp);
    switch (result.outcome) {
      case 'EMANCIPATED':
        return { accountIdentifier: result.accountIdentifier };
      case 'SECRET_TOO_SHORT':
        throw new BadRequestException(`secret trop court (minimum ${result.minLength} caractères)`);
      case 'THROTTLED':
        throw new HttpException('trop de tentatives, réessayer plus tard', HttpStatus.TOO_MANY_REQUESTS);
      default:
        // Personne inconnue, code faux, ligne non prouvée, trop jeune : LE
        // MÊME refus — rien à sonder depuis un endpoint public.
        throw new BadRequestException('émancipation refusée');
    }
  }
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== 'string' || value === '') {
    throw new BadRequestException(`${name} : chaîne requise`);
  }
  return value;
}
