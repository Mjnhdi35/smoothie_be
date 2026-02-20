import {
  Global,
  Injectable,
  Logger,
  Module,
  OnModuleInit,
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { RedisService } from './redis.service';

@Injectable()
class RedisLifecycle implements OnModuleInit {
  private readonly logger = new Logger(RedisLifecycle.name);

  constructor(private readonly redisService: RedisService) {}

  async onModuleInit(): Promise<void> {
    try {
      await this.redisService.ping();
      await this.validateWritePermissions();
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.error(`Redis init failed: ${message}`);
      throw error;
    }
  }

  private async validateWritePermissions(): Promise<void> {
    const baseKey = `health:redis:perm:${randomUUID()}`;
    const setKey = `${baseKey}:set`;
    const counterKey = `${baseKey}:counter`;

    await this.redisService.setEx(baseKey, '1', 30);
    await this.redisService.incr(counterKey);
    await this.redisService.expire(counterKey, 30);
    await this.redisService.setEx(setKey, 'member', 30);
    await this.redisService.del(baseKey, setKey, counterKey);
  }
}

@Global()
@Module({
  providers: [RedisService, RedisLifecycle],
  exports: [RedisService],
})
export class RedisModule {}
