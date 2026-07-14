import { Controller, Get, Inject, ServiceUnavailableException } from '@nestjs/common';
import { Pool } from 'pg';
import { PG_POOL } from '../db/pool';

@Controller('health')
export class HealthController {
  constructor(@Inject(PG_POOL) private readonly pool: Pool) {}

  // Le health check interroge réellement la base : un 200 sans SELECT serait
  // un trompe-l'œil (le service tournerait, les comptes non).
  @Get()
  async check(): Promise<{ status: string; database: string }> {
    try {
      await this.pool.query('SELECT 1');
      return { status: 'ok', database: 'up' };
    } catch {
      throw new ServiceUnavailableException({ status: 'down', database: 'down' });
    }
  }
}
