import { DynamicModule, Module } from '@nestjs/common';
import type { ApiAssembly } from './bootstrap/assembly';
import { PG_POOL } from './db/pool';
import { HealthController } from './health/health.controller';

/**
 * Le processus API : santé, puis les modules des lots suivants. Tout arrive
 * déjà construit et validé par l'assemblage — ce module ne fait que câbler.
 */
@Module({})
export class AppModule {
  static register(assembly: ApiAssembly): DynamicModule {
    return {
      module: AppModule,
      controllers: [HealthController],
      providers: [{ provide: PG_POOL, useValue: assembly.pool }],
    };
  }
}
