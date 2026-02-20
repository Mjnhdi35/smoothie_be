import { Controller, Get, ServiceUnavailableException } from '@nestjs/common';
import { HealthService } from './common/services/health.service';
import type {
  HealthPayload,
  ReadinessPayload,
} from './common/services/health.service';

@Controller()
export class AppController {
  constructor(private readonly healthService: HealthService) {}

  @Get('health')
  getHealth(): HealthPayload {
    return this.healthService.liveness();
  }

  @Get('health/ready')
  async getReadiness(): Promise<ReadinessPayload> {
    try {
      return await this.healthService.readiness();
    } catch {
      throw new ServiceUnavailableException(
        'Service is not ready (database or redis unavailable)',
      );
    }
  }
}
