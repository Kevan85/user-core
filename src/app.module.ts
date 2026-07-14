import { DynamicModule, Module } from '@nestjs/common';
import { AuthController } from './auth/auth.controller';
import type { AuthService } from './auth/auth.service';
import { AUTH_SERVICE } from './auth/authentication-provider';
import type { ApiAssembly } from './bootstrap/assembly';
import { PG_POOL } from './db/pool';
import { HealthController } from './health/health.controller';

/**
 * Le processus API : santé + authentification. Tout arrive déjà construit et
 * validé par l'assemblage (patron K2) — ce module ne fait que câbler.
 */
@Module({})
export class AppModule {
  static register(assembly: ApiAssembly, authService: AuthService): DynamicModule {
    return {
      module: AppModule,
      controllers: [HealthController, AuthController],
      providers: [
        { provide: PG_POOL, useValue: assembly.pool },
        { provide: AUTH_SERVICE, useValue: authService },
      ],
    };
  }
}
