import { BadRequestException } from '@nestjs/common';
import type { Request } from 'express';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import type { JwtPayload } from './types/jwt-payload.type';

describe('AuthController', () => {
  const authService = {
    register: jest.fn(),
    login: jest.fn(),
    refresh: jest.fn(),
    logout: jest.fn(),
  } as unknown as AuthService;

  const controller = new AuthController(authService);

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('throws for missing refresh token', async () => {
    const payload = {
      sub: 'u1',
      jti: 'j1',
      fp: 'fp',
      type: 'refresh',
      iat: 1,
      exp: 2,
    } as JwtPayload;

    await expect(
      controller.refresh(payload, {} as Request & { refreshToken?: string }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });
});
