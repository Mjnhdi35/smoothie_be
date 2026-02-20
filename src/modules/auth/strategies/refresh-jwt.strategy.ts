import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import type { Request } from 'express';
import { AppConfigService } from '../../../config/app-config.service';
import type { JwtPayload } from '../types/jwt-payload.type';

interface RequestWithToken extends Request {
  refreshToken?: string;
}

@Injectable()
export class RefreshJwtStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh',
) {
  constructor(private readonly appConfigService: AppConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      algorithms: ['RS256'],
      secretOrKey: appConfigService.jwt.refreshPublicKey,
      passReqToCallback: true,
    });
  }

  validate(request: RequestWithToken, payload: JwtPayload): JwtPayload {
    if (payload.type !== 'refresh') {
      throw new UnauthorizedException('Invalid refresh token type');
    }

    const authHeader = request.headers.authorization;
    request.refreshToken =
      typeof authHeader === 'string'
        ? authHeader.replace(/^Bearer\s+/i, '')
        : undefined;

    return payload;
  }
}
