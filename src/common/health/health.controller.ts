import { Controller, Get } from '@nestjs/common';
import { DatabaseService } from '../../database/database.service';
import { Public } from '../decorators/public.decorator';

@Controller()
export class HealthController {
  constructor(private readonly databaseService: DatabaseService) {}

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
    const dbHealthy = await this.databaseService.healthCheck();

    return {
      status: dbHealthy ? 'ok' : 'degraded',
      checks: {
        database: dbHealthy ? 'ok' : 'fail',
      },
      timestamp: new Date().toISOString(),
    };
  }
}
