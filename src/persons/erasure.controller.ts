import {
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  Delete,
  ForbiddenException,
  Get,
  GoneException,
  Headers,
  HttpCode,
  HttpException,
  HttpStatus,
  Inject,
  NotFoundException,
  Post,
  UnauthorizedException,
} from '@nestjs/common';
import { AUTH_PROVIDER, type AuthenticationProvider } from '../auth/authentication-provider';
import { ERASURE_SERVICE, type ErasureService, type ErasureStatus } from './erasure.service';

interface RequestBody {
  mode?: unknown;
  acknowledgeIrreversible?: unknown;
}

interface StaffBody {
  personPublicIdentifier?: unknown;
}

interface ErasureView {
  state: string;
  mode: string | null;
  /** Fin de la fenêtre de rétractation — JAMAIS une date d'effacement effectif (J+R, R inconnue). */
  effectiveAfter: string | null;
  retractable: boolean;
}

/**
 * La façade HTTP de l'effacement. BOLA : le compte vient du JETON SIGNÉ,
 * jamais du corps ni de l'URL — un compte ne demande, ne consulte et ne
 * rétracte que SON effacement. Le chemin staff vit sous /staff : le contrôle
 * de rôle est EN BASE (026), ce contrôleur ne fait que traduire FORBIDDEN.
 */
@Controller()
export class ErasureController {
  constructor(
    @Inject(ERASURE_SERVICE) private readonly erasures: ErasureService,
    @Inject(AUTH_PROVIDER) private readonly provider: AuthenticationProvider,
  ) {}

  @Post('account/erasure')
  @HttpCode(200)
  async request(
    @Body() body: RequestBody,
    @Headers('authorization') authorization?: string,
  ): Promise<ErasureView> {
    const accountId = await this.requireAccount(authorization);
    const mode = body.mode;
    if (mode !== 'IMMEDIATE' && mode !== 'DELAYED') {
      throw new BadRequestException('mode requis : IMMEDIATE ou DELAYED');
    }
    // CDC §10 n°14 : l'irréversibilité est énoncée AVANT de valider. La
    // façade exige que le client l'ait explicitement portée à la personne.
    if (mode === 'IMMEDIATE' && body.acknowledgeIrreversible !== true) {
      throw new BadRequestException(
        "l'effacement immédiat est IRRÉVERSIBLE — le champ acknowledgeIrreversible: true est requis après que la personne en a été informée",
      );
    }

    const result = await this.erasures.requestSelf(accountId, mode);
    switch (result.outcome) {
      case 'COMPLETED':
        return { state: 'COMPLETED', mode: 'IMMEDIATE', effectiveAfter: null, retractable: false };
      case 'REQUESTED':
      case 'ALREADY_REQUESTED':
        return {
          state: 'REQUESTED',
          mode: 'DELAYED',
          effectiveAfter: result.effectiveAfter.toISOString(),
          retractable: true,
        };
      case 'ALREADY_ERASED':
        throw new GoneException('personne déjà effacée — la destruction est définitive');
      case 'SOLE_RESPONSIBLE':
        throw new ConflictException(
          "impossible d'effacer le dernier responsable d'un ayant droit — un remplaçant doit d'abord être désigné (acte staff)",
        );
      case 'ACCOUNT_NOT_ACTIVE':
        throw new ForbiddenException('compte inactif');
      case 'THROTTLED':
        throw new HttpException('trop de tentatives, réessayer plus tard', HttpStatus.TOO_MANY_REQUESTS);
    }
  }

  @Delete('account/erasure')
  @HttpCode(200)
  async retract(@Headers('authorization') authorization?: string): Promise<ErasureView> {
    const accountId = await this.requireAccount(authorization);
    const result = await this.erasures.retractSelf(accountId);
    switch (result.outcome) {
      case 'RETRACTED':
        return { state: 'RETRACTED', mode: 'DELAYED', effectiveAfter: null, retractable: false };
      case 'WINDOW_CLOSED':
        throw new ConflictException(
          "fenêtre de rétractation close — l'exécution est due et ne peut plus être arrêtée",
        );
      case 'NOTHING_TO_RETRACT':
        throw new NotFoundException('aucune demande d’effacement en cours');
      case 'ACCOUNT_NOT_ACTIVE':
        throw new ForbiddenException('compte inactif');
      case 'THROTTLED':
        throw new HttpException('trop de tentatives, réessayer plus tard', HttpStatus.TOO_MANY_REQUESTS);
    }
  }

  @Get('account/erasure')
  async status(@Headers('authorization') authorization?: string): Promise<ErasureView> {
    const accountId = await this.requireAccount(authorization);
    return render(await this.erasures.status(accountId));
  }

  @Post('staff/erasures')
  @HttpCode(200)
  async staffErase(
    @Body() body: StaffBody,
    @Headers('authorization') authorization?: string,
  ): Promise<{ state: string }> {
    const actorAccountId = await this.requireAccount(authorization);
    if (typeof body.personPublicIdentifier !== 'string' || body.personPublicIdentifier === '') {
      throw new BadRequestException('personPublicIdentifier requis');
    }

    const result = await this.erasures.eraseByStaff(actorAccountId, body.personPublicIdentifier);
    switch (result.outcome) {
      case 'COMPLETED':
        return { state: 'COMPLETED' };
      case 'ALREADY_REQUESTED':
        throw new ConflictException(
          'une demande de la personne court encore — elle s’exécutera à son échéance, le staff n’écrase pas une décision de la personne',
        );
      case 'ALREADY_ERASED':
        throw new GoneException('personne déjà effacée — la destruction est définitive');
      case 'HAS_ACTIVE_ACCOUNT':
        throw new ConflictException(
          'la personne a un compte actif : elle demande son effacement elle-même (self-service)',
        );
      case 'SOLE_RESPONSIBLE':
        throw new ConflictException(
          "impossible d'effacer le dernier responsable d'un ayant droit — désigner d'abord un remplaçant",
        );
      case 'UNKNOWN_PERSON':
        throw new NotFoundException('personne inconnue');
      case 'FORBIDDEN':
        throw new ForbiddenException('acte réservé au staff');
      case 'THROTTLED':
        throw new HttpException('trop de tentatives, réessayer plus tard', HttpStatus.TOO_MANY_REQUESTS);
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

function render(status: ErasureStatus): ErasureView {
  return {
    state: status.state,
    mode: status.mode,
    effectiveAfter: status.effectiveAfter?.toISOString() ?? null,
    retractable: status.retractable,
  };
}
