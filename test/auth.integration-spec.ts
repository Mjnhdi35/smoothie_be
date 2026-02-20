import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import type { Request } from 'express';
import { Knex } from 'knex';
import { AppModule } from '../src/app.module';
import { AppConfigService } from '../src/config/app-config.service';
import { KNEX_CONNECTION } from '../src/infrastructure/database/database.constants';
import { RedisService } from '../src/infrastructure/redis/redis.service';
import { AuthService } from '../src/modules/auth/auth.service';
import type { AuthTokensDto } from '../src/modules/auth/dto/auth-tokens.dto';
import type { JwtPayload } from '../src/modules/auth/types/jwt-payload.type';

function makeRequest(userAgent = 'integration-agent'): Request {
  return {
    ip: '127.0.0.1',
    headers: { 'user-agent': userAgent },
  } as unknown as Request;
}

async function clearRedisAuthKeys(redisService: RedisService): Promise<void> {
  const keys = await redisService.keys('auth:*');
  if (keys.length > 0) {
    await redisService.del(...keys);
  }
}

describe('Auth Integration', () => {
  let moduleRef: TestingModule;
  let knex: Knex;
  let authService: AuthService;
  let redisService: RedisService;
  let jwtService: JwtService;
  let appConfigService: AppConfigService;

  beforeAll(async () => {
    moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    knex = moduleRef.get<Knex>(KNEX_CONNECTION);
    authService = moduleRef.get(AuthService);
    redisService = moduleRef.get(RedisService);
    jwtService = moduleRef.get(JwtService);
    appConfigService = moduleRef.get(AppConfigService);
  });

  afterAll(async () => {
    await moduleRef.close();
  });

  beforeEach(async () => {
    await knex.raw('TRUNCATE TABLE audit_logs, users RESTART IDENTITY CASCADE');
    await clearRedisAuthKeys(redisService);
  });

  it('register -> login -> refresh rotates token and blocks old token reuse', async () => {
    const request = makeRequest();
    const email = 'alice@example.com';
    const password = 'SuperStrongPassword123!';

    const registerTokens = await authService.register(email, password, request);
    expect(registerTokens.accessToken).toBeDefined();
    expect(registerTokens.refreshToken).toBeDefined();

    const loginTokens = await authService.login({ email, password }, request);
    expect(loginTokens).toEqual(
      expect.objectContaining({
        tokenType: 'Bearer',
        expiresIn: appConfigService.jwt.accessExpiresInSeconds,
      }),
    );

    const firstPayload = await jwtService.verifyAsync<JwtPayload>(
      loginTokens.refreshToken,
      {
        secret: appConfigService.jwt.refreshSecret,
        algorithms: ['HS256'],
        issuer: appConfigService.jwt.issuer,
        audience: appConfigService.jwt.audience,
      },
    );

    const rotatedTokens = await authService.refresh(
      firstPayload,
      loginTokens.refreshToken,
      request,
    );
    expect(rotatedTokens.refreshToken).not.toEqual(loginTokens.refreshToken);

    await expect(
      authService.refresh(firstPayload, loginTokens.refreshToken, request),
    ).rejects.toThrow('Refresh token reuse detected');
  });

  it('logout invalidates current refresh token', async () => {
    const request = makeRequest('logout-agent');
    const tokens: AuthTokensDto = await authService.register(
      'bob@example.com',
      'AnotherStrongPassword123!',
      request,
    );

    const payload = await jwtService.verifyAsync<JwtPayload>(
      tokens.refreshToken,
      {
        secret: appConfigService.jwt.refreshSecret,
        algorithms: ['HS256'],
        issuer: appConfigService.jwt.issuer,
        audience: appConfigService.jwt.audience,
      },
    );

    await authService.logout(payload, request);

    await expect(
      authService.refresh(payload, tokens.refreshToken, request),
    ).rejects.toThrow('Refresh token reuse detected');
  });
});
