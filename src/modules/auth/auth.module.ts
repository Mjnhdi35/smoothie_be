import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { LoginRateLimitGuard } from '../../common/guards/login-rate-limit.guard';
import { UsersModule } from '../users/users.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AccessTokenGuard } from './guards/access-token.guard';
import { RefreshTokenGuard } from './guards/refresh-token.guard';
import { AuthAuditService } from './services/auth-audit.service';
import { AuthSessionService } from './services/auth-session.service';
import { AuthTokenService } from './services/auth-token.service';
import { PasswordService } from './services/password.service';
import { RequestContextService } from './services/request-context.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { RefreshJwtStrategy } from './strategies/refresh-jwt.strategy';

@Module({
  imports: [
    UsersModule,
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtStrategy,
    RefreshJwtStrategy,
    AccessTokenGuard,
    RefreshTokenGuard,
    LoginRateLimitGuard,
    PasswordService,
    RequestContextService,
    AuthAuditService,
    AuthTokenService,
    AuthSessionService,
  ],
  exports: [AccessTokenGuard, RefreshTokenGuard],
})
export class AuthModule {}
