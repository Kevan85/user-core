import {
  ConflictException,
  Controller,
  Get,
  GoneException,
  Headers,
  HttpCode,
  Inject,
  NotFoundException,
  Param,
  Post,
  UnauthorizedException,
} from '@nestjs/common';
import { AUTH_PROVIDER, type AuthenticationProvider } from '../auth/authentication-provider';
import {
  ACCOUNT_INVITATIONS_SERVICE,
  type AccountInvitationsService,
  type AccountInvitationView,
} from './account-invitations.service';

@Controller('account')
export class AccountInvitationsController {
  constructor(
    @Inject(ACCOUNT_INVITATIONS_SERVICE)
    private readonly invitations: AccountInvitationsService,
    @Inject(AUTH_PROVIDER) private readonly provider: AuthenticationProvider,
  ) {}

  /** Les invitations qui portent MA ligne prouvée — et elles seules. */
  @Get('invitations')
  async list(@Headers('authorization') authorization?: string): Promise<AccountInvitationView[]> {
    const accountId = await this.requireAccount(authorization);
    return this.invitations.list(accountId);
  }

  @Post('invitations/:id/accept')
  @HttpCode(200)
  async accept(
    @Param('id') invitationId: string,
    @Headers('authorization') authorization?: string,
  ): Promise<{ status: 'ACCEPTED' }> {
    const accountId = await this.requireAccount(authorization);
    const result = await this.invitations.accept(accountId, invitationId);
    return { status: this.unwrap(result.outcome, 'ACCEPTED') };
  }

  @Post('invitations/:id/decline')
  @HttpCode(200)
  async decline(
    @Param('id') invitationId: string,
    @Headers('authorization') authorization?: string,
  ): Promise<{ status: 'DECLINED' }> {
    const accountId = await this.requireAccount(authorization);
    const result = await this.invitations.decline(accountId, invitationId);
    return { status: this.unwrap(result.outcome, 'DECLINED') };
  }

  private unwrap<T extends 'ACCEPTED' | 'DECLINED'>(
    outcome: 'ACCEPTED' | 'DECLINED' | 'ALREADY_SETTLED' | 'EXPIRED' | 'NOT_FOUND',
    expected: T,
  ): T {
    switch (outcome) {
      case expected:
        return expected;
      case 'ALREADY_SETTLED':
        throw new ConflictException('invitation déjà tranchée');
      case 'EXPIRED':
        throw new GoneException('invitation expirée');
      default:
        // Inexistante OU ligne non détenue : indiscernables, à dessein.
        throw new NotFoundException('invitation inconnue');
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
