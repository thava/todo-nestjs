import { Controller, Get, Inject } from '@nestjs/common';
import { PostgresJsDatabase } from 'drizzle-orm/postgres-js';
import { sql } from 'drizzle-orm';
import { DATABASE_CONNECTION } from '../../database/database.module';
import { Public } from '../decorators/public.decorator';
import * as schema from '../../database/schema';

@Controller()
export class HealthController {
  constructor(
    @Inject(DATABASE_CONNECTION)
    private readonly db: PostgresJsDatabase<typeof schema>,
  ) {}

  @Public()
  @Get('health')
  health() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
    };
  }

  @Public()
  @Get('readiness')
  async readiness() {
    let dbHealthy = false;
    try {
      const result = await this.db.execute(sql`SELECT 1 as health`);
      dbHealthy = result.length > 0;
    } catch (error) {
      console.error('Database health check failed:', error);
    }

    return {
      status: dbHealthy ? 'ok' : 'degraded',
      checks: {
        database: dbHealthy ? 'ok' : 'fail',
      },
      timestamp: new Date().toISOString(),
    };
  }
}
