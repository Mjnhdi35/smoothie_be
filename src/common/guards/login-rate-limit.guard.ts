import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
} from '@nestjs/common';
import type { Request } from 'express';
import { AppConfigService } from '../../config/app-config.service';
import {
  getErrorMessage,
  isRedisOperationalError,
} from '../utils/redis-error.util';
import { RedisService } from '../../infrastructure/redis/redis.service';
import {
  bruteForceEmailKey,
  bruteForceIpKey,
} from '../../modules/auth/utils/auth-redis-keys.util';

@Injectable()
export class LoginRateLimitGuard implements CanActivate {
  private readonly logger = new Logger(LoginRateLimitGuard.name);

  constructor(
    private readonly redisService: RedisService,
    private readonly appConfigService: AppConfigService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const ip = request.ip ?? 'unknown';
    const email = this.extractEmail(request.body);

    const { maxAttempts, windowSeconds } = this.appConfigService.loginRateLimit;

    const ipKey = bruteForceIpKey(ip);
    const emailKey = bruteForceEmailKey(email);

    let ipAttempts: number;
    let emailAttempts: number;
    try {
      [ipAttempts, emailAttempts] = await Promise.all([
        this.incrementCounter(ipKey, windowSeconds),
        this.incrementCounter(emailKey, windowSeconds),
      ]);
    } catch (error) {
      if (isRedisOperationalError(error)) {
        this.logger.warn(
          `Skipping login rate limit due to Redis error: ${getErrorMessage(error)}`,
        );
        return true;
      }
      throw error;
    }

    if (ipAttempts > maxAttempts || emailAttempts > maxAttempts) {
      throw new HttpException(
        'Too many login attempts',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    return true;
  }

  private extractEmail(body: unknown): string {
    if (!body || typeof body !== 'object' || !('email' in body)) {
      return 'unknown';
    }

    const maybeEmail = body.email;
    return typeof maybeEmail === 'string' ? maybeEmail : 'unknown';
  }

  private async incrementCounter(key: string, ttl: number): Promise<number> {
    const count = await this.redisService.incr(key);

    if (count === 1) {
      await this.redisService.expire(key, ttl);
    }

    return count;
  }
}
