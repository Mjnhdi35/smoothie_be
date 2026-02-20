import { BadRequestException } from '@nestjs/common';
import type { Request } from 'express';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import type { JwtPayload } from './types/jwt-payload.type';

describe('AuthController', () => {
  const authService = {
    register: jest.fn(),
    login: jest.fn(),
    me: jest.fn(),
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
      type: 'refresh',
      iat: 1,
      exp: 2,
    } as JwtPayload;

    await expect(
      controller.refresh(payload, {} as Request & { refreshToken?: string }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('delegates login to auth service', async () => {
    const loginSpy = jest
      .spyOn(authService, 'login')
      .mockResolvedValue({} as never);

    await controller.login(
      {
        email: 'alice@example.com',
        password: 'SuperStrongPassword123!',
      },
      {} as Request,
    );

    expect(loginSpy).toHaveBeenCalled();
  });

  it('delegates me to auth service', async () => {
    const meSpy = jest.spyOn(authService, 'me').mockResolvedValue({
      id: 'u1',
      email: 'alice@example.com',
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const payload = {
      sub: 'u1',
      jti: 'j1',
      type: 'access',
      iat: 1,
      exp: 2,
    } as JwtPayload;

    await controller.me(payload);
    expect(meSpy).toHaveBeenCalledWith(payload);
  });
});
