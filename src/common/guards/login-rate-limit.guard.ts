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
import { sha256 } from '../utils/crypto.util';
import { RedisService } from '../../infrastructure/redis/redis.service';

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

    const ipKey = `auth:bruteforce:ip:${sha256(ip)}`;
    const emailKey = `auth:bruteforce:email:${sha256(email.toLowerCase())}`;

    let ipAttempts: number;
    let emailAttempts: number;
    try {
      [ipAttempts, emailAttempts] = await Promise.all([
        this.incrementCounter(ipKey, windowSeconds),
        this.incrementCounter(emailKey, windowSeconds),
      ]);
    } catch (error) {
      if (this.isRedisOperationalError(error)) {
        this.logger.warn(
          `Skipping login rate limit due to Redis error: ${this.errorMessage(error)}`,
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
    const redis = this.redisService.client;
    const count = await redis.incr(key);

    if (count === 1) {
      await redis.expire(key, ttl);
    }

    return count;
  }

  private isRedisOperationalError(error: unknown): boolean {
    const message = this.errorMessage(error);
    return (
      message.includes('NOPERM') ||
      message.includes('NOAUTH') ||
      message.includes('ECONNREFUSED') ||
      message.includes('ETIMEDOUT') ||
      message.includes('EAI_AGAIN')
    );
  }

  private errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
  }
}
