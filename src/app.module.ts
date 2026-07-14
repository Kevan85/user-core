import { DynamicModule, Module } from '@nestjs/common';
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

export interface AuthWiring {
  authService: AuthService;
  sessionService: SessionService;
  provider: AuthenticationProvider;
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
      controllers: [HealthController, AuthController, SessionController],
      providers: [
        { provide: PG_POOL, useValue: assembly.pool },
        { provide: AUTH_SERVICE, useValue: auth.authService },
        { provide: SESSION_SERVICE, useValue: auth.sessionService },
        { provide: AUTH_PROVIDER, useValue: auth.provider },
      ],
    };
  }
}
