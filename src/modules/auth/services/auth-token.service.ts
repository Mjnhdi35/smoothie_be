import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { randomUUID } from 'node:crypto';
import { AppConfigService } from '../../../config/app-config.service';
import type { AuthTokensDto } from '../dto/auth-tokens.dto';

@Injectable()
export class AuthTokenService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly appConfigService: AppConfigService,
  ) {}

  async signTokenPair(
    userId: string,
    refreshJti: string,
  ): Promise<AuthTokensDto> {
    const { jwt } = this.appConfigService;

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        { jti: randomUUID(), type: 'access' as const },
        {
          secret: jwt.accessSecret,
          algorithm: 'HS256',
          expiresIn: jwt.accessExpiresInSeconds,
          subject: userId,
          issuer: jwt.issuer,
          audience: jwt.audience,
        },
      ),
      this.jwtService.signAsync(
        { jti: refreshJti, type: 'refresh' as const },
        {
          secret: jwt.refreshSecret,
          algorithm: 'HS256',
          expiresIn: jwt.refreshExpiresInSeconds,
          subject: userId,
          issuer: jwt.issuer,
          audience: jwt.audience,
        },
      ),
    ]);

    return {
      accessToken,
      refreshToken,
      tokenType: 'Bearer',
      expiresIn: jwt.accessExpiresInSeconds,
    };
  }

  ttlFromExp(exp: number): number {
    return Math.max(exp - Math.floor(Date.now() / 1000), 1);
  }

  get refreshTtlSeconds(): number {
    return this.appConfigService.jwt.refreshExpiresInSeconds;
  }
}
