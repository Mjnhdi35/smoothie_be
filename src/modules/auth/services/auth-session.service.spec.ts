import { ServiceUnavailableException } from '@nestjs/common';
import { RedisService } from '../../../infrastructure/redis/redis.service';
import { AUTH_MESSAGES } from '../auth.constants';
import { AuthSessionService } from './auth-session.service';
import { AuthTokenService } from './auth-token.service';

describe('AuthSessionService', () => {
  const ping = jest.fn();
  const get = jest.fn();
  const setEx = jest.fn();
  const del = jest.fn();
  const exists = jest.fn();
  const incr = jest.fn();
  const expire = jest.fn();
  const keys = jest.fn();

  const redisService = {
    ping,
    get,
    setEx,
    del,
    exists,
    incr,
    expire,
    keys,
  } as unknown as RedisService;

  const signTokenPair = jest.fn();
  const authTokenService = {
    signTokenPair,
    ttlFromExp: jest.fn(),
    refreshTtlSeconds: 604800,
  } as unknown as AuthTokenService;

  const service = new AuthSessionService(redisService, authTokenService);

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('issues token pair and stores refresh session', async () => {
    signTokenPair.mockResolvedValue({
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      tokenType: 'Bearer',
      expiresIn: 900,
    });
    setEx.mockResolvedValue('OK');

    const result = await service.issueTokenPair('user-1');

    expect(setEx).toHaveBeenCalledWith(
      expect.stringContaining('auth:refresh:'),
      expect.any(String),
      604800,
    );
    expect(result.accessToken).toBe('access-token');
  });

  it('maps redis failures to 503', async () => {
    signTokenPair.mockResolvedValue({
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      tokenType: 'Bearer',
      expiresIn: 900,
    });
    setEx.mockRejectedValue(new Error('timeout'));

    await expect(service.issueTokenPair('user-1')).rejects.toThrow(
      ServiceUnavailableException,
    );
  });

  it('returns reuse-detected when refresh token already used', async () => {
    get.mockResolvedValue(null);
    exists.mockResolvedValue(1);

    const result = await service.rotateRefreshToken(
      {
        sub: 'user-1',
        jti: 'old-jti',
        type: 'refresh',
        iat: 1,
        exp: 2,
      },
      'refresh-token',
    );

    expect(result).toEqual({ kind: 'reuse-detected' });
  });

  it('throws unauthorized when refresh session payload is invalid json', async () => {
    get.mockResolvedValue('not-json');

    await expect(
      service.rotateRefreshToken(
        {
          sub: 'user-1',
          jti: 'old-jti',
          type: 'refresh',
          iat: 1,
          exp: 2,
        },
        'refresh-token',
      ),
    ).rejects.toThrow(AUTH_MESSAGES.INVALID_REFRESH_TOKEN);
  });

  it('rotates refresh token successfully', async () => {
    const validSession = JSON.stringify({
      userId: 'user-1',
      tokenHash:
        '0eb17643d4e9261163783a420859c92c7d212fa9624106a12b510afbec266120',
    });
    get.mockResolvedValue(validSession);
    signTokenPair.mockResolvedValue({
      accessToken: 'access-token-new',
      refreshToken: 'refresh-token-new',
      tokenType: 'Bearer',
      expiresIn: 900,
    });
    (authTokenService.ttlFromExp as jest.Mock).mockReturnValue(1000);
    del.mockResolvedValue(1);
    setEx.mockResolvedValue('OK');

    const result = await service.rotateRefreshToken(
      {
        sub: 'user-1',
        jti: 'old-jti',
        type: 'refresh',
        iat: 1,
        exp: 2,
      },
      'refresh-token',
    );

    expect(result.kind).toBe('rotated');
    expect(del).toHaveBeenCalledWith('auth:refresh:old-jti');
    expect(setEx).toHaveBeenCalledWith('auth:refresh:used:old-jti', '1', 1000);
  });

  it('resets brute-force counters', async () => {
    del.mockResolvedValue(2);

    await service.resetBruteForceCounters('127.0.0.1', 'alice@example.com');

    expect(del).toHaveBeenCalledWith(expect.any(String), expect.any(String));
  });
});
