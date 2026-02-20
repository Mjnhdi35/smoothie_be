import {
  Injectable,
  UnauthorizedException,
  Logger,
  ConflictException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { randomUUID } from 'node:crypto';
import * as argon2 from 'argon2';
import type { Request } from 'express';
import { AppConfigService } from '../../config/app-config.service';
import { RedisService } from '../../infrastructure/redis/redis.service';
import { sha256, safeEqual } from '../../common/utils/crypto.util';
import type { JwtPayload } from './types/jwt-payload.type';
import type { AuthTokensDto } from './dto/auth-tokens.dto';
import { UsersService } from '../users/users.service';

const FALLBACK_HASH =
  '$argon2id$v=19$m=65536,t=3,p=1$RGlzY2xvc2luZ1RpbWluZw$m4cJm4FSBCfyfMra7Hmkdo0q/m+6e7iYH6g8QpW3fLM';

interface RedisMultiLike {
  set(key: string, value: string, mode: 'EX', durationSeconds: number): this;
  sadd(key: string, member: string): this;
  srem(key: string, member: string): this;
  expire(key: string, durationSeconds: number): this;
  del(key: string): this;
  exec(): Promise<unknown>;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
    private readonly appConfigService: AppConfigService,
  ) {}

  async register(
    email: string,
    password: string,
    request: Request,
  ): Promise<AuthTokensDto> {
    const normalizedEmail = this.normalizeEmail(email);
    const passwordHash = await this.hashPassword(password);
    const context = this.getRequestContext(request);

    const existing = await this.usersService.findByEmail(normalizedEmail);
    if (existing) {
      throw new ConflictException('Email is already registered');
    }

    const user = await this.usersService.createUserWithAudit({
      email: normalizedEmail,
      passwordHash,
      ...context,
    });

    return this.issueTokenPair(user.id, request);
  }

  async login(
    email: string,
    password: string,
    request: Request,
  ): Promise<AuthTokensDto> {
    const normalizedEmail = this.normalizeEmail(email);
    const context = this.getRequestContext(request);
    const user = await this.usersService.findByEmail(normalizedEmail);

    const hashedForVerify = user?.passwordHash ?? FALLBACK_HASH;
    const validPassword = await argon2
      .verify(hashedForVerify, password)
      .catch(() => false);

    if (!user || !validPassword) {
      await this.usersService.writeAudit({
        userId: user?.id ?? null,
        event: 'auth.login_failed',
        ...context,
        metadata: { email: normalizedEmail },
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    await this.resetBruteForceCounters(request, normalizedEmail);

    const tokens = await this.issueTokenPair(user.id, request);

    await this.usersService.writeAudit({
      userId: user.id,
      event: 'auth.login_success',
      ...context,
    });

    return tokens;
  }

  async refresh(
    payload: JwtPayload,
    refreshToken: string,
    request: Request,
  ): Promise<AuthTokensDto> {
    const refreshKey = this.refreshKey(payload.jti);
    const usedKey = this.usedRefreshKey(payload.jti);
    const redis = this.redisService.client;

    const fingerprintHash = this.computeFingerprint(request);
    if (!safeEqual(payload.fp, fingerprintHash)) {
      throw new UnauthorizedException('Token fingerprint mismatch');
    }

    await redis.watch(refreshKey);
    const existingSession = await redis.get(refreshKey);

    if (!existingSession) {
      await redis.unwatch();
      const used = await redis.exists(usedKey);

      if (used) {
        await this.handleRefreshReuseDetection(payload, request);
      }

      throw new UnauthorizedException('Refresh token is not valid');
    }

    let session: {
      userId: string;
      fp: string;
      tokenHash: string;
    };

    try {
      session = JSON.parse(existingSession) as {
        userId: string;
        fp: string;
        tokenHash: string;
      };
    } catch {
      await redis.unwatch();
      throw new UnauthorizedException('Refresh token is not valid');
    }

    const tokenHash = sha256(refreshToken);
    const fingerprintMatches = safeEqual(session.fp, fingerprintHash);
    const hashMatches = safeEqual(session.tokenHash, tokenHash);

    if (!fingerprintMatches || !hashMatches || session.userId !== payload.sub) {
      await redis.unwatch();
      throw new UnauthorizedException('Refresh token is not valid');
    }

    const newJti = randomUUID();
    const newTokens = await this.signTokens(
      payload.sub,
      newJti,
      fingerprintHash,
    );

    const ttlSeconds = Math.max(payload.exp - Math.floor(Date.now() / 1000), 1);
    const userSessionSetKey = this.userSessionsKey(payload.sub);

    const multi = redis.multi();
    multi.del(refreshKey);
    multi.set(usedKey, '1', 'EX', ttlSeconds);
    multi.srem(userSessionSetKey, payload.jti);

    await this.persistRefreshToken({
      userId: payload.sub,
      jti: newJti,
      refreshToken: newTokens.refreshToken,
      fingerprintHash,
      multi,
    });

    const execResult = await multi.exec();

    if (!execResult) {
      throw new UnauthorizedException('Refresh token rotation failed');
    }

    await this.usersService.writeAudit({
      userId: payload.sub,
      event: 'auth.refresh_success',
      ...this.getRequestContext(request),
      metadata: { oldJti: payload.jti, newJti },
    });

    return newTokens;
  }

  async logout(payload: JwtPayload, request: Request): Promise<void> {
    const redis = this.redisService.client;
    const refreshKey = this.refreshKey(payload.jti);
    const usedKey = this.usedRefreshKey(payload.jti);
    const ttlSeconds = Math.max(payload.exp - Math.floor(Date.now() / 1000), 1);

    await redis
      .multi()
      .del(refreshKey)
      .set(usedKey, '1', 'EX', ttlSeconds)
      .srem(this.userSessionsKey(payload.sub), payload.jti)
      .exec();

    await this.usersService.writeAudit({
      userId: payload.sub,
      event: 'auth.logout',
      ...this.getRequestContext(request),
      metadata: { jti: payload.jti },
    });
  }

  private async handleRefreshReuseDetection(
    payload: JwtPayload,
    request: Request,
  ): Promise<void> {
    this.logger.warn(`Refresh token replay detected for user ${payload.sub}`);

    await this.revokeAllSessionsForUser(payload.sub);

    await this.usersService.writeAudit({
      userId: payload.sub,
      event: 'auth.refresh_reuse_detected',
      ...this.getRequestContext(request),
      metadata: { jti: payload.jti },
    });

    throw new UnauthorizedException('Refresh token reuse detected');
  }

  private async issueTokenPair(
    userId: string,
    request: Request,
  ): Promise<AuthTokensDto> {
    const jti = randomUUID();
    const fingerprintHash = this.computeFingerprint(request);
    const tokens = await this.signTokens(userId, jti, fingerprintHash);

    await this.persistRefreshToken({
      userId,
      jti,
      refreshToken: tokens.refreshToken,
      fingerprintHash,
    });

    return tokens;
  }

  private async signTokens(
    userId: string,
    refreshJti: string,
    fingerprintHash: string,
  ): Promise<AuthTokensDto> {
    const { jwt } = this.appConfigService;

    const accessPayload = {
      sub: userId,
      jti: randomUUID(),
      fp: fingerprintHash,
      type: 'access' as const,
    };

    const refreshPayload = {
      sub: userId,
      jti: refreshJti,
      fp: fingerprintHash,
      type: 'refresh' as const,
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(accessPayload, {
        privateKey: jwt.accessPrivateKey,
        algorithm: 'RS256',
        expiresIn: jwt.accessExpiresInSeconds,
      }),
      this.jwtService.signAsync(refreshPayload, {
        privateKey: jwt.refreshPrivateKey,
        algorithm: 'RS256',
        expiresIn: jwt.refreshExpiresInSeconds,
      }),
    ]);

    return {
      accessToken,
      refreshToken,
      tokenType: 'Bearer',
      expiresIn: jwt.accessExpiresInSeconds,
    };
  }

  private async persistRefreshToken(params: {
    userId: string;
    jti: string;
    refreshToken: string;
    fingerprintHash: string;
    multi?: RedisMultiLike;
  }): Promise<void> {
    const { userId, jti, refreshToken, fingerprintHash, multi } = params;
    const refreshKey = this.refreshKey(jti);
    const userSessionSetKey = this.userSessionsKey(userId);
    const ttl = this.appConfigService.jwt.refreshExpiresInSeconds;
    const value = JSON.stringify({
      userId,
      fp: fingerprintHash,
      tokenHash: sha256(refreshToken),
    });

    if (multi) {
      multi.set(refreshKey, value, 'EX', ttl);
      multi.sadd(userSessionSetKey, jti);
      multi.expire(userSessionSetKey, ttl);
      return;
    }

    await this.redisService.client
      .multi()
      .set(refreshKey, value, 'EX', ttl)
      .sadd(userSessionSetKey, jti)
      .expire(userSessionSetKey, ttl)
      .exec();
  }

  private async revokeAllSessionsForUser(userId: string): Promise<void> {
    const redis = this.redisService.client;
    const userSessionSetKey = this.userSessionsKey(userId);
    const sessions = await redis.smembers(userSessionSetKey);

    if (sessions.length === 0) {
      await redis.del(userSessionSetKey);
      return;
    }

    const transaction = redis.multi();
    for (const jti of sessions) {
      transaction.del(this.refreshKey(jti));
    }
    transaction.del(userSessionSetKey);

    await transaction.exec();
  }

  private async resetBruteForceCounters(
    request: Request,
    email: string,
  ): Promise<void> {
    const ipKey = `auth:bruteforce:ip:${sha256(this.getRequestIp(request))}`;
    const emailKey = `auth:bruteforce:email:${sha256(email)}`;

    await this.redisService.client.del(ipKey, emailKey);
  }

  private normalizeEmail(email: string): string {
    return email.trim().toLowerCase();
  }

  private hashPassword(password: string): Promise<string> {
    return argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 1,
    });
  }

  private getRequestContext(request: Request): {
    ip: string;
    userAgent: string;
  } {
    return {
      ip: this.getRequestIp(request),
      userAgent: this.getUserAgent(request),
    };
  }

  private computeFingerprint(request: Request): string {
    const ip = this.getRequestIp(request);
    const userAgent = this.getUserAgent(request);
    const secret = this.appConfigService.jwt.fingerprintSecret;

    return sha256(`${secret}|${ip}|${userAgent}`);
  }

  private getRequestIp(request: Request): string {
    return request.ip ?? 'unknown';
  }

  private getUserAgent(request: Request): string {
    const userAgentHeader = request.headers['user-agent'];
    return typeof userAgentHeader === 'string' ? userAgentHeader : 'unknown';
  }

  private refreshKey(jti: string): string {
    return `auth:refresh:${jti}`;
  }

  private usedRefreshKey(jti: string): string {
    return `auth:refresh:used:${jti}`;
  }

  private userSessionsKey(userId: string): string {
    return `auth:user_refresh:${userId}`;
  }
}
