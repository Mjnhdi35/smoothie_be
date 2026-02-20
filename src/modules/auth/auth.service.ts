import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { Request } from 'express';
import { randomUUID } from 'node:crypto';
import { sha256, safeEqual } from '../../common/utils/crypto.util';
import { AppConfigService } from '../../config/app-config.service';
import { RedisService } from '../../infrastructure/redis/redis.service';
import { UsersService } from '../users/users.service';
import type { UserEntity } from '../users/entities/user.entity';
import type { AuthMeDto } from './dto/auth-me.dto';
import type { AuthTokensDto } from './dto/auth-tokens.dto';
import type { LoginDto } from './dto/login.dto';
import { PasswordService } from './services/password.service';
import { RequestContextService } from './services/request-context.service';
import type { JwtPayload } from './types/jwt-payload.type';

const INVALID_REFRESH_TOKEN_MESSAGE = 'Refresh token is not valid';

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

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
    private readonly appConfigService: AppConfigService,
    private readonly passwordService: PasswordService,
    private readonly requestContextService: RequestContextService,
  ) {}

  async register(
    email: string,
    password: string,
    request: Request,
  ): Promise<AuthTokensDto> {
    const normalizedEmail = this.passwordService.normalizeEmail(email);
    const passwordHash = await this.passwordService.hash(password);
    const context = this.requestContextService.getAuditContext(request);

    const existing = await this.usersService.findByEmail(normalizedEmail);
    if (existing) {
      throw new ConflictException('Email is already registered');
    }

    const user = await this.usersService.createUserWithAudit({
      email: normalizedEmail,
      passwordHash,
      ...context,
    });

    return this.issueTokenPair(user.id);
  }

  async loginByProvider(
    payload: LoginDto,
    request: Request,
  ): Promise<AuthTokensDto> {
    switch (payload.provider ?? 'password') {
      case 'password':
        if (!payload.email || !payload.password) {
          throw new BadRequestException('Missing email or password');
        }
        return this.loginWithPassword(payload.email, payload.password, request);
      case 'google':
        return this.loginWithGoogle(payload.googleIdToken);
      default:
        throw new BadRequestException('Unsupported auth provider');
    }
  }

  async me(payload: JwtPayload): Promise<AuthMeDto> {
    const user = await this.usersService.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return this.toAuthMe(user);
  }

  async refresh(
    payload: JwtPayload,
    refreshToken: string,
    request: Request,
  ): Promise<AuthTokensDto> {
    const refreshKey = this.refreshKey(payload.jti);
    const usedKey = this.usedRefreshKey(payload.jti);
    const redis = this.redisService.client;

    await redis.watch(refreshKey);
    const existingSession = await redis.get(refreshKey);

    if (!existingSession) {
      await redis.unwatch();
      const used = await redis.exists(usedKey);

      if (used) {
        await this.handleRefreshReuseDetection(payload, request);
      }

      throw new UnauthorizedException(INVALID_REFRESH_TOKEN_MESSAGE);
    }

    const session = await this.parseRefreshSession(existingSession, redis);
    const hashMatches = safeEqual(session.tokenHash, sha256(refreshToken));

    if (!hashMatches || session.userId !== payload.sub) {
      await redis.unwatch();
      throw new UnauthorizedException(INVALID_REFRESH_TOKEN_MESSAGE);
    }

    const newJti = randomUUID();
    const newTokens = await this.signTokens(payload.sub, newJti);
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
      multi,
    });

    const execResult = await multi.exec();
    if (!execResult) {
      throw new UnauthorizedException('Refresh token rotation failed');
    }

    await this.usersService.writeAudit({
      userId: payload.sub,
      event: 'auth.refresh_success',
      ...this.requestContextService.getAuditContext(request),
      metadata: { oldJti: payload.jti, newJti },
    });

    return newTokens;
  }

  async logout(payload: JwtPayload, request: Request): Promise<void> {
    const ttlSeconds = Math.max(payload.exp - Math.floor(Date.now() / 1000), 1);

    await this.redisService.client
      .multi()
      .del(this.refreshKey(payload.jti))
      .set(this.usedRefreshKey(payload.jti), '1', 'EX', ttlSeconds)
      .srem(this.userSessionsKey(payload.sub), payload.jti)
      .exec();

    await this.usersService.writeAudit({
      userId: payload.sub,
      event: 'auth.logout',
      ...this.requestContextService.getAuditContext(request),
      metadata: { jti: payload.jti },
    });
  }

  private async loginWithPassword(
    email: string,
    password: string,
    request: Request,
  ): Promise<AuthTokensDto> {
    const normalizedEmail = this.passwordService.normalizeEmail(email);
    const context = this.requestContextService.getAuditContext(request);
    const user = await this.usersService.findByEmail(normalizedEmail);
    const validPassword = await this.passwordService.verify(
      user?.passwordHash,
      password,
    );

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
    const tokens = await this.issueTokenPair(user.id);

    await this.usersService.writeAudit({
      userId: user.id,
      event: 'auth.login_success',
      ...context,
    });

    return tokens;
  }

  private loginWithGoogle(
    googleIdToken: string | undefined,
  ): Promise<AuthTokensDto> {
    if (!googleIdToken) {
      throw new BadRequestException('Missing google id token');
    }

    // Placeholder for next step:
    // verify Google ID token, upsert local user, then issue token pair.
    throw new BadRequestException('Google login is not configured yet');
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
      ...this.requestContextService.getAuditContext(request),
      metadata: { jti: payload.jti },
    });

    throw new UnauthorizedException('Refresh token reuse detected');
  }

  private async issueTokenPair(userId: string): Promise<AuthTokensDto> {
    const jti = randomUUID();
    const tokens = await this.signTokens(userId, jti);

    await this.persistRefreshToken({
      userId,
      jti,
      refreshToken: tokens.refreshToken,
    });

    return tokens;
  }

  private async signTokens(
    userId: string,
    refreshJti: string,
  ): Promise<AuthTokensDto> {
    const { jwt } = this.appConfigService;

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        { sub: userId, jti: randomUUID(), type: 'access' as const },
        {
          privateKey: jwt.accessPrivateKey,
          algorithm: 'RS256',
          expiresIn: jwt.accessExpiresInSeconds,
        },
      ),
      this.jwtService.signAsync(
        { sub: userId, jti: refreshJti, type: 'refresh' as const },
        {
          privateKey: jwt.refreshPrivateKey,
          algorithm: 'RS256',
          expiresIn: jwt.refreshExpiresInSeconds,
        },
      ),
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
    multi?: RedisMultiLike;
  }): Promise<void> {
    const { userId, jti, refreshToken, multi } = params;
    const refreshKey = this.refreshKey(jti);
    const userSessionSetKey = this.userSessionsKey(userId);
    const ttl = this.appConfigService.jwt.refreshExpiresInSeconds;
    const value = JSON.stringify({ userId, tokenHash: sha256(refreshToken) });

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
    const { ipKey, emailKey } = this.bruteForceKeys(request, email);
    await this.redisService.client.del(ipKey, emailKey);
  }

  private bruteForceKeys(
    request: Request,
    email: string,
  ): { ipKey: string; emailKey: string } {
    return {
      ipKey: `auth:bruteforce:ip:${sha256(this.requestContextService.getIp(request))}`,
      emailKey: `auth:bruteforce:email:${sha256(email)}`,
    };
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

  private refreshKey(jti: string): string {
    return `auth:refresh:${jti}`;
  }

  private usedRefreshKey(jti: string): string {
    return `auth:refresh:used:${jti}`;
  }

  private userSessionsKey(userId: string): string {
    return `auth:user_refresh:${userId}`;
  }

  private toAuthMe(user: UserEntity): AuthMeDto {
    return {
      id: user.id,
      email: user.email,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }
}
