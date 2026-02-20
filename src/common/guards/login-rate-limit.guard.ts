import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import type { Request } from 'express';
import { AppConfigService } from '../../config/app-config.service';
import { sha256 } from '../utils/crypto.util';
import { RedisService } from '../../infrastructure/redis/redis.service';

@Injectable()
export class LoginRateLimitGuard implements CanActivate {
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

    const [ipAttempts, emailAttempts] = await Promise.all([
      this.incrementCounter(ipKey, windowSeconds),
      this.incrementCounter(emailKey, windowSeconds),
    ]);

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
}
