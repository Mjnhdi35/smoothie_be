import { ConflictException, UnauthorizedException } from '@nestjs/common';
import type { Request } from 'express';
import { AppConfigService } from '../../config/app-config.service';
import { RedisService } from '../../infrastructure/redis/redis.service';
import { UsersService } from '../users/users.service';
import { PasswordService } from './services/password.service';
import { RequestContextService } from './services/request-context.service';
import { AuthService } from './auth.service';
import { JwtService } from '@nestjs/jwt';
import type { JwtPayload } from './types/jwt-payload.type';

function makeRequest(): Request {
  return {
    ip: '127.0.0.1',
    headers: { 'user-agent': 'jest-agent' },
  } as unknown as Request;
}

describe('AuthService', () => {
  const findByEmail = jest.fn();
  const createUserWithAudit = jest.fn();
  const writeAudit = jest.fn();
  const usersService = {
    findByEmail,
    findById: jest.fn(),
    createUserWithAudit,
    writeAudit,
  } as unknown as UsersService;

  const signAsync = jest.fn();
  const jwtService = {
    signAsync,
  } as unknown as JwtService;

  const redisMulti = {
    set: jest.fn().mockReturnThis(),
    sadd: jest.fn().mockReturnThis(),
    srem: jest.fn().mockReturnThis(),
    expire: jest.fn().mockReturnThis(),
    del: jest.fn().mockReturnThis(),
    exec: jest.fn(),
  };

  const redisDel = jest.fn();
  const redisClient = {
    multi: jest.fn(() => redisMulti),
    del: redisDel,
    watch: jest.fn(),
    get: jest.fn(),
    unwatch: jest.fn(),
    exists: jest.fn(),
  };

  const redisService = {
    client: redisClient,
  } as unknown as RedisService;

  const appConfigService = {
    jwt: {
      accessSecret: 'access-secret',
      refreshSecret: 'refresh-secret',
      issuer: 'api-smoothie',
      audience: 'api-smoothie-users',
      accessExpiresIn: '15m',
      refreshExpiresIn: '7d',
      accessExpiresInSeconds: 900,
      refreshExpiresInSeconds: 604800,
    },
  } as AppConfigService;

  const passwordService = {
    normalizeEmail: jest.fn(),
    hash: jest.fn(),
    verify: jest.fn(),
  } as unknown as PasswordService;

  const requestContextService = {
    getAuditContext: jest.fn(),
    getIp: jest.fn(),
  } as unknown as RequestContextService;

  const service = new AuthService(
    usersService,
    jwtService,
    redisService,
    appConfigService,
    passwordService,
    requestContextService,
  );

  beforeEach(() => {
    jest.clearAllMocks();
    redisMulti.exec.mockResolvedValue([]);
    redisDel.mockResolvedValue(1);
  });

  it('registers user and returns token pair', async () => {
    (passwordService.normalizeEmail as jest.Mock).mockReturnValue(
      'alice@example.com',
    );
    (passwordService.hash as jest.Mock).mockResolvedValue('hashed-password');
    (requestContextService.getAuditContext as jest.Mock).mockReturnValue({
      ip: '127.0.0.1',
      userAgent: 'jest-agent',
    });
    findByEmail.mockResolvedValue(null);
    createUserWithAudit.mockResolvedValue({
      id: 'user-1',
    });
    signAsync
      .mockResolvedValueOnce('access-token')
      .mockResolvedValueOnce('refresh-token');

    const result = await service.register(
      ' Alice@Example.com ',
      'strong-password-123',
      makeRequest(),
    );

    expect(createUserWithAudit).toHaveBeenCalledWith({
      email: 'alice@example.com',
      passwordHash: 'hashed-password',
      ip: '127.0.0.1',
      userAgent: 'jest-agent',
    });
    expect(result).toMatchObject({
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      tokenType: 'Bearer',
      expiresIn: 900,
    });
  });

  it('throws conflict when registering existing email', async () => {
    (passwordService.normalizeEmail as jest.Mock).mockReturnValue(
      'alice@example.com',
    );
    (passwordService.hash as jest.Mock).mockResolvedValue('hashed-password');
    (requestContextService.getAuditContext as jest.Mock).mockReturnValue({
      ip: '127.0.0.1',
      userAgent: 'jest-agent',
    });
    findByEmail.mockResolvedValue({ id: 'user-1' });

    await expect(
      service.register(
        'alice@example.com',
        'strong-password-123',
        makeRequest(),
      ),
    ).rejects.toBeInstanceOf(ConflictException);
  });

  it('logs audit and throws unauthorized on invalid login', async () => {
    (passwordService.normalizeEmail as jest.Mock).mockReturnValue(
      'alice@example.com',
    );
    (requestContextService.getAuditContext as jest.Mock).mockReturnValue({
      ip: '127.0.0.1',
      userAgent: 'jest-agent',
    });
    findByEmail.mockResolvedValue(null);
    (passwordService.verify as jest.Mock).mockResolvedValue(false);

    await expect(
      service.login(
        { email: 'alice@example.com', password: 'wrong-password' },
        makeRequest(),
      ),
    ).rejects.toBeInstanceOf(UnauthorizedException);

    expect(writeAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        event: 'auth.login_failed',
        metadata: { email: 'alice@example.com' },
      }),
    );
  });

  it('logs success and resets bruteforce counters on valid login', async () => {
    (passwordService.normalizeEmail as jest.Mock).mockReturnValue(
      'alice@example.com',
    );
    (requestContextService.getAuditContext as jest.Mock).mockReturnValue({
      ip: '127.0.0.1',
      userAgent: 'jest-agent',
    });
    (requestContextService.getIp as jest.Mock).mockReturnValue('127.0.0.1');
    findByEmail.mockResolvedValue({
      id: 'user-1',
      passwordHash: 'stored-hash',
    });
    (passwordService.verify as jest.Mock).mockResolvedValue(true);
    signAsync
      .mockResolvedValueOnce('access-token')
      .mockResolvedValueOnce('refresh-token');

    await service.login(
      { email: 'alice@example.com', password: 'strong-password-123' },
      makeRequest(),
    );

    expect(redisDel).toHaveBeenCalled();
    expect(writeAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'user-1',
        event: 'auth.login_success',
      }),
    );
  });

  it('rejects refresh when token hash mismatches', async () => {
    const payload = {
      sub: 'user-1',
      jti: 'jti-1',
      type: 'refresh',
      iat: 1,
      exp: Math.floor(Date.now() / 1000) + 3600,
    } as JwtPayload;

    redisClient.watch.mockResolvedValue(undefined);
    redisClient.get.mockResolvedValue(
      JSON.stringify({ userId: 'user-1', tokenHash: 'wrong-hash' }),
    );
    redisClient.unwatch.mockResolvedValue(undefined);

    await expect(
      service.refresh(payload, 'refresh-token', makeRequest()),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('returns current user profile for me', async () => {
    const user = {
      id: 'user-1',
      email: 'alice@example.com',
      passwordHash: 'hash',
      createdAt: new Date('2026-01-01T00:00:00.000Z'),
      updatedAt: new Date('2026-01-02T00:00:00.000Z'),
    };
    (usersService.findById as jest.Mock).mockResolvedValue(user);

    await expect(
      service.me({
        sub: 'user-1',
        jti: 'jti-1',
        type: 'access',
        iat: 1,
        exp: 2,
      }),
    ).resolves.toEqual({
      id: 'user-1',
      email: 'alice@example.com',
      createdAt: new Date('2026-01-01T00:00:00.000Z'),
      updatedAt: new Date('2026-01-02T00:00:00.000Z'),
    });
  });
});
