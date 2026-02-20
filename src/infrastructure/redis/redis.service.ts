import { Injectable } from '@nestjs/common';
import { AppConfigService } from '../../config/app-config.service';

@Injectable()
export class RedisService {
  private readonly baseUrl: string;
  private readonly token: string;
  private readonly timeoutMs: number;
  private readonly retryAttempts: number;
  private readonly retryDelayMs: number;

  constructor(appConfigService: AppConfigService) {
    const redisConfig = appConfigService.redis;
    this.baseUrl = redisConfig.url.replace(/\/+$/, '');
    this.token = redisConfig.token;
    this.timeoutMs = redisConfig.timeoutMs;
    this.retryAttempts = redisConfig.retryAttempts;
    this.retryDelayMs = redisConfig.retryDelayMs;
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
    let lastError: Error | null = null;
    const totalAttempts = this.retryAttempts + 1;

    for (let attempt = 1; attempt <= totalAttempts; attempt += 1) {
      try {
        const response = await this.post(path);
        const payload = await this.readPayload<T>(response);

        if (response.ok && !payload.error) {
          return payload.result as T;
        }

        const requestError = new Error(
          payload.error ??
            `Upstash command failed (${response.status}) for ${this.baseUrl}`,
        );

        if (!this.shouldRetry(response.status, requestError, attempt)) {
          throw requestError;
        }

        lastError = requestError;
      } catch (error: unknown) {
        const requestError =
          error instanceof Error ? error : new Error(String(error));
        if (!this.shouldRetry(undefined, requestError, attempt)) {
          throw requestError;
        }
        lastError = requestError;
      }

      await this.sleep(this.retryDelayMs * attempt);
    }

    if (lastError) {
      throw new Error(
        `Upstash request failed after ${totalAttempts} attempts: ${lastError.message}`,
      );
    }

    throw new Error('Upstash request failed without specific error');
  }

  private async post(path: string): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      return await fetch(`${this.baseUrl}/${path}`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.token}`,
        },
        signal: controller.signal,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(
        `Upstash REST request failed for ${this.baseUrl}: ${message}. Check UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN.`,
      );
    } finally {
      clearTimeout(timeout);
    }
  }

  private async readPayload<T>(
    response: Response,
  ): Promise<{ result?: T; error?: string }> {
    try {
      return (await response.json()) as { result?: T; error?: string };
    } catch {
      return {
        error: `Upstash response is not valid JSON (${response.status})`,
      };
    }
  }

  private shouldRetry(
    status: number | undefined,
    error: Error,
    attempt: number,
  ): boolean {
    if (attempt > this.retryAttempts) {
      return false;
    }

    if (status === 429 || (typeof status === 'number' && status >= 500)) {
      return true;
    }

    const message = error.message.toLowerCase();
    return (
      message.includes('timeout') ||
      message.includes('timed out') ||
      message.includes('abort') ||
      message.includes('eai_again') ||
      message.includes('fetch failed') ||
      message.includes('econnreset') ||
      message.includes('etimedout') ||
      message.includes('econnrefused')
    );
  }

  private async sleep(ms: number): Promise<void> {
    if (ms <= 0) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, ms));
  }
}
