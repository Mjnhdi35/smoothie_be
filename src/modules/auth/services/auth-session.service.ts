import {
  Injectable,
  Logger,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { sha256, safeEqual } from '../../../common/utils/crypto.util';
import {
  getErrorMessage,
  isRedisOperationalError,
} from '../../../common/utils/redis-error.util';
import { RedisService } from '../../../infrastructure/redis/redis.service';
import { AUTH_MESSAGES } from '../auth.constants';
import type { AuthTokensDto } from '../dto/auth-tokens.dto';
import type { JwtPayload } from '../types/jwt-payload.type';
import {
  bruteForceEmailKey,
  bruteForceIpKey,
  refreshSessionKey,
  usedRefreshSessionKey,
} from '../utils/auth-redis-keys.util';
import { AuthTokenService } from './auth-token.service';

interface RefreshSession {
  userId: string;
  tokenHash: string;
}

type RefreshResult =
  | { kind: 'rotated'; tokens: AuthTokensDto; oldJti: string; newJti: string }
  | { kind: 'reuse-detected' };

@Injectable()
export class AuthSessionService {
  private readonly logger = new Logger(AuthSessionService.name);

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
    }, 'issueTokenPair');
  }

  async rotateRefreshToken(
    payload: JwtPayload,
    refreshToken: string,
  ): Promise<RefreshResult> {
    return this.withRedisGuard(async () => {
      const refreshKey = refreshSessionKey(payload.jti);
      const usedKey = usedRefreshSessionKey(payload.jti);
      const existingSession = await this.redisService.get(refreshKey);

      if (!existingSession) {
        const used = await this.redisService.exists(usedKey);
        if (used > 0) {
          return { kind: 'reuse-detected' };
        }
        throw new UnauthorizedException(AUTH_MESSAGES.INVALID_REFRESH_TOKEN);
      }

      const parsed = this.parseRefreshSession(existingSession);
      if (!this.isRefreshSessionValid(parsed, payload.sub, refreshToken)) {
        throw new UnauthorizedException(AUTH_MESSAGES.INVALID_REFRESH_TOKEN);
      }

      const newJti = randomUUID();
      const tokens = await this.authTokenService.signTokenPair(
        payload.sub,
        newJti,
      );
      const ttlSeconds = this.authTokenService.ttlFromExp(payload.exp);

      await this.redisService.del(refreshKey);
      await this.redisService.setEx(usedKey, '1', ttlSeconds);
      await this.persistRefreshToken(payload.sub, newJti, tokens.refreshToken);

      return { kind: 'rotated', tokens, oldJti: payload.jti, newJti };
    }, 'rotateRefreshToken');
  }

  async logout(payload: JwtPayload): Promise<void> {
    await this.withRedisGuard(async () => {
      const ttlSeconds = this.authTokenService.ttlFromExp(payload.exp);
      await this.redisService.del(refreshSessionKey(payload.jti));
      await this.redisService.setEx(
        usedRefreshSessionKey(payload.jti),
        '1',
        ttlSeconds,
      );
    }, 'logout');
  }

  async resetBruteForceCounters(ip: string, email: string): Promise<void> {
    await this.withRedisGuard(async () => {
      await this.redisService.del(
        bruteForceIpKey(ip),
        bruteForceEmailKey(email),
      );
    }, 'resetBruteForceCounters');
  }

  private async persistRefreshToken(
    userId: string,
    jti: string,
    refreshToken: string,
  ): Promise<void> {
    const key = refreshSessionKey(jti);
    const ttl = this.authTokenService.refreshTtlSeconds;
    const value = JSON.stringify({ userId, tokenHash: sha256(refreshToken) });
    await this.redisService.setEx(key, value, ttl);
  }

  private parseRefreshSession(session: string): RefreshSession {
    try {
      return JSON.parse(session) as RefreshSession;
    } catch {
      throw new UnauthorizedException(AUTH_MESSAGES.INVALID_REFRESH_TOKEN);
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

  private async withRedisGuard<T>(
    operation: () => Promise<T>,
    operationName: string,
  ): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (!isRedisOperationalError(error)) {
        throw error;
      }
      this.logger.error(
        `Redis operation failed (${operationName}): ${getErrorMessage(error)}`,
      );
      throw new ServiceUnavailableException(AUTH_MESSAGES.SERVICE_UNAVAILABLE);
    }
  }
}
