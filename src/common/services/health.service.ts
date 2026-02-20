import { Inject, Injectable } from '@nestjs/common';
import { Knex } from 'knex';
import { KNEX_CONNECTION } from '../../infrastructure/database/database.constants';
import { RedisService } from '../../infrastructure/redis/redis.service';

export interface HealthPayload {
  ok: true;
  timestamp: string;
}

export interface ReadinessPayload extends HealthPayload {
  checks: {
    database: 'up';
    redis: 'up';
  };
}

@Injectable()
export class HealthService {
  constructor(
    @Inject(KNEX_CONNECTION) private readonly db: Knex,
    private readonly redisService: RedisService,
  ) {}

  liveness(): HealthPayload {
    return {
      ok: true,
      timestamp: new Date().toISOString(),
    };
  }

  async readiness(): Promise<ReadinessPayload> {
    await Promise.all([this.db.raw('select 1'), this.redisService.ping()]);

    return {
      ok: true,
      timestamp: new Date().toISOString(),
      checks: {
        database: 'up',
        redis: 'up',
      },
    };
  }
}
