import {
  Global,
  Inject,
  Injectable,
  Logger,
  Module,
  OnModuleInit,
  OnApplicationShutdown,
} from '@nestjs/common';
import Redis from 'ioredis';
import { AppConfigService } from '../../config/app-config.service';
import { REDIS_CLIENT } from './redis.constants';
import { RedisService } from './redis.service';

const REDIS_CLIENT_OPTIONS = {
  lazyConnect: false,
  maxRetriesPerRequest: 3,
  enableReadyCheck: false,
} as const;

@Injectable()
class RedisLifecycle implements OnModuleInit, OnApplicationShutdown {
  private readonly logger = new Logger(RedisLifecycle.name);

  constructor(@Inject(REDIS_CLIENT) private readonly redisClient: Redis) {}

  async onModuleInit(): Promise<void> {
    this.redisClient.on('error', (error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.error(`Redis error: ${message}`);
    });

    try {
      await this.redisClient.ping();
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes('NOAUTH')) {
        throw new Error(
          'Redis authentication failed: check REDIS_URL credentials.',
        );
      }
      throw error;
    }
  }

  async onApplicationShutdown(): Promise<void> {
    await this.redisClient.quit();
  }
}

@Global()
@Module({
  providers: [
    {
      provide: REDIS_CLIENT,
      inject: [AppConfigService],
      useFactory: (appConfig: AppConfigService): Redis => {
        return new Redis(appConfig.redis.url, REDIS_CLIENT_OPTIONS);
      },
    },
    RedisLifecycle,
    RedisService,
  ],
  exports: [REDIS_CLIENT, RedisService],
})
export class RedisModule {}
