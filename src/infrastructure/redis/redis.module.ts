import {
  Global,
  Inject,
  Injectable,
  Logger,
  Module,
  OnModuleInit,
  OnApplicationShutdown,
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import Redis from 'ioredis';
import { AppConfigService } from '../../config/app-config.service';
import { REDIS_CLIENT } from './redis.constants';
import { RedisService } from './redis.service';

const REDIS_CLIENT_OPTIONS = {
  lazyConnect: false,
  maxRetriesPerRequest: 1,
  enableReadyCheck: false,
  connectTimeout: 2500,
  commandTimeout: 2500,
  enableOfflineQueue: false,
  retryStrategy: (attempt: number) => Math.min(attempt * 100, 500),
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
      await this.validateWritePermissions();
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      if (message.includes('NOAUTH')) {
        throw new Error(
          'Redis authentication failed: check REDIS_URL credentials.',
        );
      }
      if (message.includes('NOPERM')) {
        throw new Error(
          'Redis permission denied: REDIS_URL user must allow SET/SADD/SREM/EXPIRE/DEL/INCR.',
        );
      }
      throw error;
    }
  }

  async onApplicationShutdown(): Promise<void> {
    await this.redisClient.quit();
  }

  private async validateWritePermissions(): Promise<void> {
    const baseKey = `health:redis:perm:${randomUUID()}`;
    const setKey = `${baseKey}:set`;

    await this.redisClient
      .multi()
      .set(baseKey, '1', 'EX', 30)
      .sadd(setKey, 'member')
      .srem(setKey, 'member')
      .expire(setKey, 30)
      .incr(`${baseKey}:counter`)
      .del(baseKey, setKey, `${baseKey}:counter`)
      .exec();
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
