import {
  ConflictException,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';
import { UsersService } from '../users/users.service';
import { AuthService } from './auth.service';
import { PasswordService } from './services/password.service';
import { AuthSessionService } from './services/auth-session.service';
import { AuthAuditService } from './services/auth-audit.service';
import type { JwtPayload } from './types/jwt-payload.type';

function makeRequest(): Request {
  return {
    ip: '127.0.0.1',
    headers: { 'user-agent': 'jest-agent' },
  } as unknown as Request;
}

describe('AuthService', () => {
  const findByEmail = jest.fn();
  const findById = jest.fn();
  const createUserWithAudit = jest.fn();
  const deleteById = jest.fn();
  const usersService = {
    findByEmail,
    findById,
    createUserWithAudit,
    deleteById,
  } as unknown as UsersService;

  const normalizeEmail = jest.fn();
  const hashPassword = jest.fn();
  const verifyPassword = jest.fn();
  const passwordService = {
    normalizeEmail,
    hash: hashPassword,
    verify: verifyPassword,
  } as unknown as PasswordService;

  const issueTokenPair = jest.fn();
  const resetBruteForceCounters = jest.fn();
  const rotateRefreshToken = jest.fn();
  const logout = jest.fn();
  const authSessionService = {
    issueTokenPair,
    resetBruteForceCounters,
    rotateRefreshToken,
    logout,
  } as unknown as AuthSessionService;

  const writeAudit = jest.fn();
  const authAuditService = {
    write: writeAudit,
  } as unknown as AuthAuditService;

  const service = new AuthService(
    usersService,
    passwordService,
    authSessionService,
    authAuditService,
  );

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('registers user and returns token pair', async () => {
    normalizeEmail.mockReturnValue('alice@example.com');
    hashPassword.mockResolvedValue('hashed-password');
    findByEmail.mockResolvedValue(null);
    createUserWithAudit.mockResolvedValue({ id: 'user-1' });
    issueTokenPair.mockResolvedValue({
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      tokenType: 'Bearer',
      expiresIn: 900,
    });

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
    normalizeEmail.mockReturnValue('alice@example.com');
    hashPassword.mockResolvedValue('hashed-password');
    findByEmail.mockResolvedValue({ id: 'user-1' });

    await expect(
      service.register(
        'alice@example.com',
        'strong-password-123',
        makeRequest(),
      ),
    ).rejects.toBeInstanceOf(ConflictException);
  });

  it('rolls back created user when session service is unavailable', async () => {
    normalizeEmail.mockReturnValue('alice@example.com');
    hashPassword.mockResolvedValue('hashed-password');
    findByEmail.mockResolvedValue(null);
    createUserWithAudit.mockResolvedValue({ id: 'user-1' });
    issueTokenPair.mockRejectedValue(
      new ServiceUnavailableException(
        'Authentication service is temporarily unavailable',
      ),
    );

    await expect(
      service.register(
        'alice@example.com',
        'strong-password-123',
        makeRequest(),
      ),
    ).rejects.toThrow('Authentication service is temporarily unavailable');

    expect(deleteById).toHaveBeenCalledWith('user-1');
  });

  it('logs audit and throws unauthorized on invalid login', async () => {
    normalizeEmail.mockReturnValue('alice@example.com');
    findByEmail.mockResolvedValue(null);
    verifyPassword.mockResolvedValue(false);

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
    normalizeEmail.mockReturnValue('alice@example.com');
    findByEmail.mockResolvedValue({
      id: 'user-1',
      passwordHash: 'stored-hash',
    });
    verifyPassword.mockResolvedValue(true);
    issueTokenPair.mockResolvedValue({
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      tokenType: 'Bearer',
      expiresIn: 900,
    });

    await service.login(
      { email: 'alice@example.com', password: 'strong-password-123' },
      makeRequest(),
    );

    expect(resetBruteForceCounters).toHaveBeenCalledWith(
      '127.0.0.1',
      'alice@example.com',
    );
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

    rotateRefreshToken.mockRejectedValue(
      new UnauthorizedException('Refresh token is not valid'),
    );

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
    findById.mockResolvedValue(user);

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
