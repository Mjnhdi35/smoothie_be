import { UnauthorizedException } from '@nestjs/common';
import type { Request } from 'express';
import { AppConfigService } from '../../../config/app-config.service';
import { UsersService } from '../../users/users.service';
import { RefreshJwtStrategy } from './refresh-jwt.strategy';

describe('RefreshJwtStrategy', () => {
  const usersService = {
    findById: jest.fn(),
  } as unknown as UsersService;

  const appConfigService = {
    jwt: {
      refreshPublicKey: 'refresh-public-key',
      issuer: 'api-smoothie',
      audience: 'api-smoothie-users',
    },
  } as AppConfigService;

  const strategy = new RefreshJwtStrategy(appConfigService, usersService);

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('throws when token type is not refresh', async () => {
    (usersService.findById as jest.Mock).mockResolvedValue({ id: 'user-1' });
    const request = {
      headers: { authorization: 'Bearer token' },
    } as unknown as Request & { refreshToken?: string };

    await expect(
      strategy.validate(request, {
        sub: 'user-1',
        jti: 'jti-1',
        type: 'access',
        iat: 1,
        exp: 2,
      }),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('stores refresh token and returns payload', async () => {
    (usersService.findById as jest.Mock).mockResolvedValue({ id: 'user-1' });
    const request = {
      headers: { authorization: 'Bearer refresh-token-value' },
    } as unknown as Request & { refreshToken?: string };

    const payload = await strategy.validate(request, {
      sub: 'user-1',
      jti: 'jti-1',
      type: 'refresh',
      iat: 1,
      exp: 2,
    });

    expect(payload.sub).toBe('user-1');
    expect(request.refreshToken).toBe('refresh-token-value');
  });
});
