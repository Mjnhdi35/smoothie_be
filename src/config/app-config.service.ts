import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { durationToSeconds } from '../common/utils/duration.util';

type PostgresConfig =
  | { url: string }
  | {
      host: string;
      port: number;
      database: string;
      user: string;
      password: string;
      ssl: boolean;
    };

type RedisConfig =
  | { url: string }
  | {
      host: string;
      port: number;
      username?: string;
      password?: string;
      tls: boolean;
    };

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
      .filter(Boolean);
  }

  get trustProxy(): boolean {
    const value = this.getOptional('TRUST_PROXY');
    return value ? value === 'true' : this.isProduction;
  }

  get pinoLevel(): string {
    return this.getOptional('PINO_LEVEL') ?? 'info';
  }

  get postgres(): PostgresConfig {
    const url = this.getOptional('DATABASE_URL');
    if (url) {
      return { url };
    }

    return {
      host: this.get('POSTGRES_HOST'),
      port: Number(this.get('POSTGRES_PORT')),
      database: this.get('POSTGRES_DB'),
      user: this.get('POSTGRES_USER'),
      password: this.get('POSTGRES_PASSWORD'),
      ssl: this.get('POSTGRES_SSL') === 'true',
    };
  }

  get redis(): RedisConfig {
    const url = this.getOptional('REDIS_URL');
    if (url) {
      return { url };
    }

    return {
      host: this.get('REDIS_HOST'),
      port: Number(this.get('REDIS_PORT')),
      username: this.getOptional('REDIS_USERNAME'),
      password: this.getOptional('REDIS_PASSWORD'),
      tls: this.get('REDIS_TLS') === 'true',
    };
  }

  get jwt(): {
    accessSecret: string;
    refreshSecret: string;
    issuer: string;
    audience: string;
    accessExpiresIn: string;
    refreshExpiresIn: string;
    accessExpiresInSeconds: number;
    refreshExpiresInSeconds: number;
  } {
    const accessExpiresIn = this.get('JWT_ACCESS_EXPIRES_IN');
    const refreshExpiresIn = this.get('JWT_REFRESH_EXPIRES_IN');

    return {
      accessSecret: this.get('JWT_ACCESS_SECRET'),
      refreshSecret: this.get('JWT_REFRESH_SECRET'),
      issuer: this.getOptional('JWT_ISSUER') ?? 'api-smoothie',
      audience: this.getOptional('JWT_AUDIENCE') ?? 'api-smoothie-users',
      accessExpiresIn,
      refreshExpiresIn,
      accessExpiresInSeconds: durationToSeconds(accessExpiresIn),
      refreshExpiresInSeconds: durationToSeconds(refreshExpiresIn),
    };
  }

  get loginRateLimit(): { maxAttempts: number; windowSeconds: number } {
    return {
      maxAttempts: Number(
        this.getOptional('LOGIN_RATE_LIMIT_MAX_ATTEMPTS') ?? '5',
      ),
      windowSeconds: Number(
        this.getOptional('LOGIN_RATE_LIMIT_WINDOW_SECONDS') ?? '900',
      ),
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

}
