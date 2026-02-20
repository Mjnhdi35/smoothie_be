import {
  Global,
  Inject,
  Injectable,
  Module,
  OnApplicationShutdown,
} from '@nestjs/common';
import Redis from 'ioredis';
import { AppConfigService } from '../../config/app-config.service';
import { REDIS_CLIENT } from './redis.constants';
import { RedisService } from './redis.service';

const REDIS_CLIENT_OPTIONS = {
  lazyConnect: false,
  maxRetriesPerRequest: 3,
  enableReadyCheck: true,
} as const;

@Injectable()
class RedisLifecycle implements OnApplicationShutdown {
  constructor(@Inject(REDIS_CLIENT) private readonly redisClient: Redis) {}

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
        const redisConfig = appConfig.redis;

        if ('url' in redisConfig) {
          return new Redis(redisConfig.url, REDIS_CLIENT_OPTIONS);
        }

        const { host, port, username, password, tls } = redisConfig;

        return new Redis({
          host,
          port,
          ...(username ? { username } : {}),
          ...(password ? { password } : {}),
          tls: tls ? {} : undefined,
          ...REDIS_CLIENT_OPTIONS,
        });
      },
    },
    RedisLifecycle,
    RedisService,
  ],
  exports: [REDIS_CLIENT, RedisService],
})
export class RedisModule {}
