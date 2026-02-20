import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import type { Request } from 'express';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { LoginRateLimitGuard } from '../../common/guards/login-rate-limit.guard';
import { AuthService } from './auth.service';
import { AuthMeDto } from './dto/auth-me.dto';
import { AuthTokensDto } from './dto/auth-tokens.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { AccessTokenGuard } from './guards/access-token.guard';
import { RefreshTokenGuard } from './guards/refresh-token.guard';
import type { JwtPayload } from './types/jwt-payload.type';

interface RequestWithRefreshToken extends Request {
  refreshToken?: string;
}

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(
    @Body() body: RegisterDto,
    @Req() request: Request,
  ): Promise<AuthTokensDto> {
    return this.authService.register(body.email, body.password, request);
  }

  @UseGuards(LoginRateLimitGuard)
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() body: LoginDto,
    @Req() request: Request,
  ): Promise<AuthTokensDto> {
    return this.authService.login(body, request);
  }

  @UseGuards(AccessTokenGuard)
  @Get('me')
  async me(@CurrentUser() payload: JwtPayload): Promise<AuthMeDto> {
    return this.authService.me(payload);
  }

  @UseGuards(RefreshTokenGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @CurrentUser() payload: JwtPayload,
    @Req() request: RequestWithRefreshToken,
  ): Promise<AuthTokensDto> {
    if (!request.refreshToken) {
      throw new BadRequestException('Missing refresh token');
    }

    return this.authService.refresh(payload, request.refreshToken, request);
  }

  @UseGuards(RefreshTokenGuard)
  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(
    @CurrentUser() payload: JwtPayload,
    @Req() request: Request,
  ): Promise<void> {
    await this.authService.logout(payload, request);
  }
}
