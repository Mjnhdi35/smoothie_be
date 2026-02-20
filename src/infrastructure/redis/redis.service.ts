import { Injectable } from '@nestjs/common';
import { AppConfigService } from '../../config/app-config.service';

@Injectable()
export class RedisService {
  private readonly baseUrl: string;
  private readonly token: string;

  constructor(appConfigService: AppConfigService) {
    this.baseUrl = appConfigService.redis.url.replace(/\/+$/, '');
    this.token = appConfigService.redis.token;
  }

  ping(): Promise<string> {
    return this.command<string>('PING');
  }

  get(key: string): Promise<string | null> {
    return this.command<string | null>('GET', key);
  }

  setEx(key: string, value: string, ttlSeconds: number): Promise<'OK'> {
    return this.command<'OK'>('SET', key, value, 'EX', String(ttlSeconds));
  }

  del(...keys: string[]): Promise<number> {
    return this.command<number>('DEL', ...keys);
  }

  exists(key: string): Promise<number> {
    return this.command<number>('EXISTS', key);
  }

  incr(key: string): Promise<number> {
    return this.command<number>('INCR', key);
  }

  expire(key: string, ttlSeconds: number): Promise<number> {
    return this.command<number>('EXPIRE', key, String(ttlSeconds));
  }

  keys(pattern: string): Promise<string[]> {
    return this.command<string[]>('KEYS', pattern);
  }

  private async command<T>(...parts: string[]): Promise<T> {
    const path = parts.map((part) => encodeURIComponent(part)).join('/');
    const response = await fetch(`${this.baseUrl}/${path}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.token}`,
      },
    });

    const payload = (await response.json()) as {
      result?: T;
      error?: string;
    };

    if (!response.ok || payload.error) {
      throw new Error(
        payload.error ?? `Upstash command failed (${response.status})`,
      );
    }

    return payload.result as T;
  }
}
