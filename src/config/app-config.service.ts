import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { durationToSeconds } from '../common/utils/duration.util';

@Injectable()
export class AppConfigService {
  constructor(private readonly configService: ConfigService) {}

  get nodeEnv(): string {
    return this.get('NODE_ENV');
  }

  get isProduction(): boolean {
    return this.nodeEnv === 'production';
  }

  get port(): number {
    return Number(this.get('PORT'));
  }

  get corsOrigins(): string[] {
    return this.get('CORS_ORIGIN')
      .split(',')
      .map((origin) => origin.trim())
      .filter((origin) => origin.length > 0);
  }

  get trustProxy(): boolean {
    return this.get('TRUST_PROXY') === 'true';
  }

  get pinoLevel(): string {
    return this.get('PINO_LEVEL');
  }

  get postgres(): {
    url?: string;
    host: string;
    port: number;
    database: string;
    user: string;
    password: string;
    ssl: boolean;
  } {
    const url = this.getOptional('DATABASE_URL');
    if (url) {
      return {
        url,
        host: '',
        port: 0,
        database: '',
        user: '',
        password: '',
        ssl: true,
      };
    }

    return {
      url: undefined,
      host: this.get('POSTGRES_HOST'),
      port: Number(this.get('POSTGRES_PORT')),
      database: this.get('POSTGRES_DB'),
      user: this.get('POSTGRES_USER'),
      password: this.get('POSTGRES_PASSWORD'),
      ssl: this.get('POSTGRES_SSL') === 'true',
    };
  }

  get redis(): {
    host: string;
    port: number;
    username: string;
    password: string;
    tls: boolean;
  } {
    return {
      host: this.get('REDIS_HOST'),
      port: Number(this.get('REDIS_PORT')),
      username: this.get('REDIS_USERNAME'),
      password: this.get('REDIS_PASSWORD'),
      tls: this.get('REDIS_TLS') === 'true',
    };
  }

  get jwt(): {
    accessPrivateKey: string;
    accessPublicKey: string;
    refreshPrivateKey: string;
    refreshPublicKey: string;
    accessExpiresIn: string;
    refreshExpiresIn: string;
    accessExpiresInSeconds: number;
    refreshExpiresInSeconds: number;
    fingerprintSecret: string;
  } {
    const accessExpiresIn = this.get('JWT_ACCESS_EXPIRES_IN');
    const refreshExpiresIn = this.get('JWT_REFRESH_EXPIRES_IN');

    return {
      accessPrivateKey: this.normalizePem(this.get('JWT_ACCESS_PRIVATE_KEY')),
      accessPublicKey: this.normalizePem(this.get('JWT_ACCESS_PUBLIC_KEY')),
      refreshPrivateKey: this.normalizePem(this.get('JWT_REFRESH_PRIVATE_KEY')),
      refreshPublicKey: this.normalizePem(this.get('JWT_REFRESH_PUBLIC_KEY')),
      accessExpiresIn,
      refreshExpiresIn,
      accessExpiresInSeconds: durationToSeconds(accessExpiresIn),
      refreshExpiresInSeconds: durationToSeconds(refreshExpiresIn),
      fingerprintSecret: this.get('JWT_FINGERPRINT_SECRET'),
    };
  }

  get loginRateLimit(): { maxAttempts: number; windowSeconds: number } {
    return {
      maxAttempts: Number(this.get('LOGIN_RATE_LIMIT_MAX_ATTEMPTS')),
      windowSeconds: Number(this.get('LOGIN_RATE_LIMIT_WINDOW_SECONDS')),
    };
  }

  private get(key: string): string {
    const value = this.configService.get<string>(key);

    if (!value) {
      throw new Error(`Missing env key: ${key}`);
    }

    return value;
  }

  private getOptional(key: string): string | undefined {
    const value = this.configService.get<string>(key);
    return value && value.trim().length > 0 ? value : undefined;
  }

  private normalizePem(value: string): string {
    return value.replace(/\\n/g, '\n');
  }
}
