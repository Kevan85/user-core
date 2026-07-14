import { DynamicModule, Module } from '@nestjs/common';
import { ProfileController } from './accounts/profile.controller';
import { PROFILE_SERVICE, type ProfileService } from './accounts/profile.service';
import { RegistrationController } from './accounts/registration.controller';
import {
  REGISTRATION_SERVICE,
  type RegistrationService,
} from './accounts/registration.service';
import { AuthController } from './auth/auth.controller';
import type { AuthService } from './auth/auth.service';
import {
  AUTH_PROVIDER,
  AUTH_SERVICE,
  type AuthenticationProvider,
} from './auth/authentication-provider';
import { SessionController } from './auth/session.controller';
import { SESSION_SERVICE, type SessionService } from './auth/session.service';
import type { ApiAssembly } from './bootstrap/assembly';
import { PG_POOL } from './db/pool';
import { HealthController } from './health/health.controller';
import { AccountInvitationsController } from './invitations/account-invitations.controller';
import {
  ACCOUNT_INVITATIONS_SERVICE,
  type AccountInvitationsService,
} from './invitations/account-invitations.service';
import { CatalogController } from './catalog/catalog.controller';
import { CATALOG_SERVICE, type CatalogService } from './catalog/catalog.service';
import { PhoneController } from './phone/phone.controller';
import { PHONE_SERVICE, type PhoneService } from './phone/phone.service';

export interface AuthWiring {
  authService: AuthService;
  sessionService: SessionService;
  provider: AuthenticationProvider;
  phoneService: PhoneService;
  catalogService: CatalogService;
  registrationService: RegistrationService;
  profileService: ProfileService;
  accountInvitationsService: AccountInvitationsService;
}

/**
 * Le processus API : santé + authentification + sessions. Tout arrive déjà
 * construit et validé par l'assemblage (patron K2) — ce module ne fait que
 * câbler.
 */
@Module({})
export class AppModule {
  static register(assembly: ApiAssembly, auth: AuthWiring): DynamicModule {
    return {
      module: AppModule,
      controllers: [
        HealthController,
        AuthController,
        RegistrationController,
        SessionController,
        PhoneController,
        CatalogController,
        ProfileController,
        AccountInvitationsController,
      ],
      providers: [
        { provide: PG_POOL, useValue: assembly.pool },
        { provide: AUTH_SERVICE, useValue: auth.authService },
        { provide: SESSION_SERVICE, useValue: auth.sessionService },
        { provide: AUTH_PROVIDER, useValue: auth.provider },
        { provide: PHONE_SERVICE, useValue: auth.phoneService },
        { provide: CATALOG_SERVICE, useValue: auth.catalogService },
        { provide: REGISTRATION_SERVICE, useValue: auth.registrationService },
        { provide: PROFILE_SERVICE, useValue: auth.profileService },
        { provide: ACCOUNT_INVITATIONS_SERVICE, useValue: auth.accountInvitationsService },
      ],
    };
  }
}
