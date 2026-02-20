import {
  ConflictException,
  Injectable,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';
import { UsersService } from '../users/users.service';
import type { UserEntity } from '../users/entities/user.entity';
import { AUTH_EVENTS, AUTH_MESSAGES } from './auth.constants';
import type { AuthMeDto } from './dto/auth-me.dto';
import type { AuthTokensDto } from './dto/auth-tokens.dto';
import type { LoginDto } from './dto/login.dto';
import { AuthAuditService } from './services/auth-audit.service';
import { AuthSessionService } from './services/auth-session.service';
import { PasswordService } from './services/password.service';
import type { JwtPayload } from './types/jwt-payload.type';

type UsersAuthGateway = Pick<
  UsersService,
  'findByEmail' | 'findById' | 'createUserWithAudit' | 'deleteById'
>;

@Injectable()
export class AuthService {
  private readonly usersService: UsersAuthGateway;

  constructor(
    usersService: UsersService,
    private readonly passwordService: PasswordService,
    private readonly authSessionService: AuthSessionService,
    private readonly authAuditService: AuthAuditService,
  ) {
    this.usersService = usersService;
  }

  async register(
    email: string,
    password: string,
    request: Request,
  ): Promise<AuthTokensDto> {
    const normalizedEmail = this.passwordService.normalizeEmail(email);
    const passwordHash = await this.passwordService.hash(password);
    const context = this.extractAuditContext(request);

    const existing = await this.usersService.findByEmail(normalizedEmail);
    if (existing) {
      throw new ConflictException('Email is already registered');
    }

    const user = await this.usersService.createUserWithAudit({
      email: normalizedEmail,
      passwordHash,
      ...context,
    });

    try {
      return await this.authSessionService.issueTokenPair(user.id);
    } catch (error) {
      if (error instanceof ServiceUnavailableException) {
        await this.usersService.deleteById(user.id);
      }
      throw error;
    }
  }

  async login(payload: LoginDto, request: Request): Promise<AuthTokensDto> {
    const normalizedEmail = this.passwordService.normalizeEmail(payload.email);
    const user = await this.usersService.findByEmail(normalizedEmail);
    const validPassword = await this.passwordService.verify(
      user?.passwordHash,
      payload.password,
    );

    if (!user || !validPassword) {
      await this.authAuditService.write({
        request,
        userId: user?.id ?? null,
        event: AUTH_EVENTS.LOGIN_FAILED,
        metadata: { email: normalizedEmail },
      });
      throw new UnauthorizedException(AUTH_MESSAGES.INVALID_CREDENTIALS);
    }

    await this.authSessionService.resetBruteForceCounters(
      request.ip ?? 'unknown',
      normalizedEmail,
    );
    const tokens = await this.authSessionService.issueTokenPair(user.id);
    await this.authAuditService.write({
      request,
      userId: user.id,
      event: AUTH_EVENTS.LOGIN_SUCCESS,
    });
    return tokens;
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
    const result = await this.authSessionService.rotateRefreshToken(
      payload,
      refreshToken,
    );

    if (result.kind === 'reuse-detected') {
      await this.authAuditService.write({
        request,
        userId: payload.sub,
        event: AUTH_EVENTS.REFRESH_REUSE_DETECTED,
        metadata: { jti: payload.jti },
      });
      throw new UnauthorizedException(AUTH_MESSAGES.REFRESH_TOKEN_REUSE);
    }

    await this.authAuditService.write({
      request,
      userId: payload.sub,
      event: AUTH_EVENTS.REFRESH_SUCCESS,
      metadata: { oldJti: result.oldJti, newJti: result.newJti },
    });

    return result.tokens;
  }

  async logout(payload: JwtPayload, request: Request): Promise<void> {
    await this.authSessionService.logout(payload);
    await this.authAuditService.write({
      request,
      userId: payload.sub,
      event: AUTH_EVENTS.LOGOUT,
      metadata: { jti: payload.jti },
    });
  }

  private extractAuditContext(request: Request): {
    ip: string | null;
    userAgent: string | null;
  } {
    return {
      ip: request.ip ?? null,
      userAgent:
        typeof request.headers['user-agent'] === 'string'
          ? request.headers['user-agent']
          : null,
    };
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
