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
  Param,
  Post,
  UnauthorizedException,
} from '@nestjs/common';
import { AUTH_PROVIDER, type AuthenticationProvider } from '../auth/authentication-provider';
import type { ProofChannel } from '../proving/line-ownership-prover';
import { PHONE_SERVICE, type PhoneService } from './phone.service';

interface DeclareBody {
  phone?: unknown;
}
interface ProofBody {
  channel?: unknown;
}
interface VerifyBody {
  code?: unknown;
}

// Les canaux acceptés par l'API sont ceux de la DOCTRINE : SMS ou appel.
// « whatsapp » n'est pas refusé par une liste — il n'existe pas dans le type.
const CHANNELS: readonly ProofChannel[] = ['SMS', 'CALL'];

@Controller('phone')
export class PhoneController {
  constructor(
    @Inject(PHONE_SERVICE) private readonly phone: PhoneService,
    @Inject(AUTH_PROVIDER) private readonly provider: AuthenticationProvider,
  ) {}

  /** Déclarer un numéro. N'ENVOIE RIEN (vérification paresseuse, CDC §6.3). */
  @Post('claims')
  @HttpCode(201)
  async declare(
    @Body() body: DeclareBody,
    @Headers('authorization') authorization?: string,
  ): Promise<{ claimId: string }> {
    const accountId = await this.requireAccount(authorization);
    if (typeof body.phone !== 'string' || body.phone === '') {
      throw new BadRequestException('phone requis');
    }
    const result = await this.phone.declare(accountId, body.phone);
    if (result.outcome === 'INVALID_PHONE') {
      throw new BadRequestException('numéro invalide (format E.164 attendu)');
    }
    return { claimId: result.claimId };
  }

  /**
   * Demander une preuve — appelé au PREMIER PAIEMENT, jamais à l'inscription.
   * Aucun endpoint d'authentification ne peut atteindre ce chemin.
   */
  @Post('claims/:claimId/proofs')
  @HttpCode(202)
  async requestProof(
    @Param('claimId') claimId: string,
    @Body() body: ProofBody,
    @Headers('authorization') authorization?: string,
  ): Promise<{ proofId: string }> {
    const accountId = await this.requireAccount(authorization);
    const channel = body.channel;
    if (typeof channel !== 'string' || !CHANNELS.includes(channel as ProofChannel)) {
      throw new BadRequestException('channel doit valoir SMS ou CALL');
    }

    const result = await this.phone.requestProof(accountId, claimId, channel as ProofChannel);
    switch (result.outcome) {
      case 'SENT':
        return { proofId: result.proofId };
      case 'REFUSED_CAP':
        // La ligne a déjà trop sonné : on protège le téléphone d'un TIERS.
        throw new HttpException(
          'trop de demandes pour cette ligne, réessayer plus tard',
          HttpStatus.TOO_MANY_REQUESTS,
        );
      case 'REFUSED_PENDING':
        throw new HttpException('une demande est déjà en cours', HttpStatus.CONFLICT);
      case 'UNDELIVERABLE':
        throw new HttpException(
          'livraison impossible, réessayer',
          HttpStatus.SERVICE_UNAVAILABLE,
        );
      case 'INTEGRITY_VIOLATION':
        // On ne dit rien de plus au client : la cause est interne et grave.
        throw new HttpException('demande impossible', HttpStatus.CONFLICT);
      default:
        throw new ForbiddenException('revendication introuvable');
    }
  }

  /** Présenter le code reçu par SMS ou par appel. */
  @Post('claims/:claimId/verify')
  @HttpCode(200)
  async verify(
    @Param('claimId') claimId: string,
    @Body() body: VerifyBody,
    @Headers('authorization') authorization?: string,
  ): Promise<{ status: 'PROVEN' }> {
    const accountId = await this.requireAccount(authorization);
    if (typeof body.code !== 'string' || body.code === '') {
      throw new BadRequestException('code requis');
    }
    const result = await this.phone.verify(accountId, claimId, body.code);
    if (result.outcome === 'PROVEN') {
      return { status: 'PROVEN' };
    }
    // WRONG, EXPIRED, EXHAUSTED, ALREADY_SETTLED, NOT_FOUND : refus unique.
    // Le porteur d'un code n'apprend rien de l'état interne.
    throw new UnauthorizedException('code invalide');
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
