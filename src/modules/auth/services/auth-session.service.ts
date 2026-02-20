import {
  Injectable,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import type Redis from 'ioredis';
import { randomUUID } from 'node:crypto';
import { sha256, safeEqual } from '../../../common/utils/crypto.util';
import { isRedisOperationalError } from '../../../common/utils/redis-error.util';
import { RedisService } from '../../../infrastructure/redis/redis.service';
import type { AuthTokensDto } from '../dto/auth-tokens.dto';
import type { JwtPayload } from '../types/jwt-payload.type';
import {
  bruteForceEmailKey,
  bruteForceIpKey,
  refreshSessionKey,
  usedRefreshSessionKey,
  userRefreshSessionsKey,
} from '../utils/auth-redis-keys.util';
import { AuthTokenService } from './auth-token.service';

const INVALID_REFRESH_TOKEN_MESSAGE = 'Refresh token is not valid';
const AUTH_SERVICE_UNAVAILABLE_MESSAGE =
  'Authentication service is temporarily unavailable';

interface RedisMultiLike {
  set(key: string, value: string, mode: 'EX', durationSeconds: number): this;
  sadd(key: string, member: string): this;
  srem(key: string, member: string): this;
  expire(key: string, durationSeconds: number): this;
  del(key: string): this;
  exec(): Promise<unknown>;
}

interface RefreshSession {
  userId: string;
  tokenHash: string;
}

type RefreshResult =
  | { kind: 'rotated'; tokens: AuthTokensDto; oldJti: string; newJti: string }
  | { kind: 'reuse-detected' };

@Injectable()
export class AuthSessionService {
  constructor(
    private readonly redisService: RedisService,
    private readonly authTokenService: AuthTokenService,
  ) {}

  async issueTokenPair(userId: string): Promise<AuthTokensDto> {
    return this.withRedisGuard(async () => {
      const jti = randomUUID();
      const tokens = await this.authTokenService.signTokenPair(userId, jti);
      await this.persistRefreshToken(userId, jti, tokens.refreshToken);
      return tokens;
    });
  }

  async rotateRefreshToken(
    payload: JwtPayload,
    refreshToken: string,
  ): Promise<RefreshResult> {
    return this.withRedisGuard(async () => {
      const refreshKey = refreshSessionKey(payload.jti);
      const usedKey = usedRefreshSessionKey(payload.jti);
      const redis = this.redisService.client;

      await redis.watch(refreshKey);
      const existingSession = await redis.get(refreshKey);

      if (!existingSession) {
        await redis.unwatch();
        const used = await redis.exists(usedKey);
        if (used) {
          await this.revokeAllSessionsForUser(payload.sub);
          return { kind: 'reuse-detected' };
        }
        throw new UnauthorizedException(INVALID_REFRESH_TOKEN_MESSAGE);
      }

      const parsed = await this.parseRefreshSession(existingSession, redis);
      if (!this.isRefreshSessionValid(parsed, payload.sub, refreshToken)) {
        await redis.unwatch();
        throw new UnauthorizedException(INVALID_REFRESH_TOKEN_MESSAGE);
      }

      const newJti = randomUUID();
      const tokens = await this.authTokenService.signTokenPair(
        payload.sub,
        newJti,
      );
      const ttlSeconds = this.authTokenService.ttlFromExp(payload.exp);
      const userSessionSetKey = userRefreshSessionsKey(payload.sub);

      const multi = this.createRedisMulti(redis);
      multi.del(refreshKey);
      multi.set(usedKey, '1', 'EX', ttlSeconds);
      multi.srem(userSessionSetKey, payload.jti);
      await this.persistRefreshToken(
        payload.sub,
        newJti,
        tokens.refreshToken,
        multi,
      );

      const execResult = await multi.exec();
      if (!execResult) {
        throw new UnauthorizedException('Refresh token rotation failed');
      }

      return { kind: 'rotated', tokens, oldJti: payload.jti, newJti };
    });
  }

  async logout(payload: JwtPayload): Promise<void> {
    await this.withRedisGuard(async () => {
      const ttlSeconds = this.authTokenService.ttlFromExp(payload.exp);
      const multi = this.createRedisMulti(this.redisService.client);
      await multi
        .del(refreshSessionKey(payload.jti))
        .set(usedRefreshSessionKey(payload.jti), '1', 'EX', ttlSeconds)
        .srem(userRefreshSessionsKey(payload.sub), payload.jti)
        .exec();
    });
  }

  async resetBruteForceCounters(ip: string, email: string): Promise<void> {
    await this.withRedisGuard(async () => {
      await this.redisService.client.del(
        bruteForceIpKey(ip),
        bruteForceEmailKey(email),
      );
    });
  }

  private async persistRefreshToken(
    userId: string,
    jti: string,
    refreshToken: string,
    multi?: RedisMultiLike,
  ): Promise<void> {
    const refreshKey = refreshSessionKey(jti);
    const userSessionSetKey = userRefreshSessionsKey(userId);
    const ttl = this.authTokenService.refreshTtlSeconds;
    const value = JSON.stringify({ userId, tokenHash: sha256(refreshToken) });

    if (multi) {
      multi.set(refreshKey, value, 'EX', ttl);
      multi.sadd(userSessionSetKey, jti);
      multi.expire(userSessionSetKey, ttl);
      return;
    }

    await this.createRedisMulti(this.redisService.client)
      .set(refreshKey, value, 'EX', ttl)
      .sadd(userSessionSetKey, jti)
      .expire(userSessionSetKey, ttl)
      .exec();
  }

  private async revokeAllSessionsForUser(userId: string): Promise<void> {
    const redis = this.redisService.client;
    const userSessionSetKey = userRefreshSessionsKey(userId);
    const sessions = await redis.smembers(userSessionSetKey);

    if (sessions.length === 0) {
      await redis.del(userSessionSetKey);
      return;
    }

    const multi = this.createRedisMulti(redis);
    for (const jti of sessions) {
      multi.del(refreshSessionKey(jti));
    }
    multi.del(userSessionSetKey);
    await multi.exec();
  }

  private async parseRefreshSession(
    session: string,
    redis: { unwatch(): Promise<unknown> },
  ): Promise<RefreshSession> {
    try {
      return JSON.parse(session) as RefreshSession;
    } catch {
      await redis.unwatch();
      throw new UnauthorizedException(INVALID_REFRESH_TOKEN_MESSAGE);
    }
  }

  private isRefreshSessionValid(
    session: RefreshSession,
    userId: string,
    refreshToken: string,
  ): boolean {
    return (
      session.userId === userId &&
      safeEqual(session.tokenHash, sha256(refreshToken))
    );
  }

  private async withRedisGuard<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (!isRedisOperationalError(error)) {
        throw error;
      }
      throw new ServiceUnavailableException(AUTH_SERVICE_UNAVAILABLE_MESSAGE);
    }
  }

  private createRedisMulti(redis: Redis): RedisMultiLike {
    return redis.multi() as unknown as RedisMultiLike;
  }
}
