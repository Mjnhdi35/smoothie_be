import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import type { Request } from 'express';
import { AppConfigService } from '../../../config/app-config.service';
import { UsersService } from '../../users/users.service';
import type { JwtPayload } from '../types/jwt-payload.type';

interface RequestWithToken extends Request {
  refreshToken?: string;
}

@Injectable()
export class RefreshJwtStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(
    private readonly appConfigService: AppConfigService,
    private readonly usersService: UsersService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      algorithms: ['HS256'],
      secretOrKey: appConfigService.jwt.refreshSecret,
      issuer: appConfigService.jwt.issuer,
      audience: appConfigService.jwt.audience,
      passReqToCallback: true,
    });
  }

  async validate(
    request: RequestWithToken,
    payload: JwtPayload,
  ): Promise<JwtPayload> {
    if (!payload.sub || !payload.jti || payload.type !== 'refresh') {
      throw new UnauthorizedException('Invalid refresh token type');
    }

    const user = await this.usersService.findById(payload.sub);
    if (!user) {
      throw new UnauthorizedException('User no longer exists');
    }

    const authHeader = request.headers.authorization;
    request.refreshToken =
      typeof authHeader === 'string'
        ? authHeader.replace(/^Bearer\s+/i, '')
        : undefined;

    return payload;
  }
}
