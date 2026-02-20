import { UnauthorizedException } from '@nestjs/common';
import { AppConfigService } from '../../../config/app-config.service';
import { UsersService } from '../../users/users.service';
import { JwtStrategy } from './jwt.strategy';

describe('JwtStrategy', () => {
  const usersService = {
    findById: jest.fn(),
  } as unknown as UsersService;

  const appConfigService = {
    jwt: {
      accessPublicKey: 'access-public-key',
      issuer: 'api-smoothie',
      audience: 'api-smoothie-users',
    },
  } as AppConfigService;

  const strategy = new JwtStrategy(appConfigService, usersService);

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('throws when token type is not access', async () => {
    await expect(
      strategy.validate({
        sub: 'user-1',
        jti: 'jti-1',
        type: 'refresh',
        iat: 1,
        exp: 2,
      }),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('throws when user no longer exists', async () => {
    (usersService.findById as jest.Mock).mockResolvedValue(null);

    await expect(
      strategy.validate({
        sub: 'user-1',
        jti: 'jti-1',
        type: 'access',
        iat: 1,
        exp: 2,
      }),
    ).rejects.toBeInstanceOf(UnauthorizedException);
  });
});
