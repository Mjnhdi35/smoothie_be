import { AppConfigService } from '../../config/app-config.service';
import { RedisService } from './redis.service';

describe('RedisService', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
    jest.resetAllMocks();
  });

  function createService(overrides?: {
    timeoutMs?: number;
    retryAttempts?: number;
    retryDelayMs?: number;
  }): RedisService {
    const appConfigService = {
      redis: {
        url: 'https://example.upstash.io',
        token: 'token',
        timeoutMs: overrides?.timeoutMs ?? 50,
        retryAttempts: overrides?.retryAttempts ?? 1,
        retryDelayMs: overrides?.retryDelayMs ?? 0,
      },
    } as unknown as AppConfigService;

    return new RedisService(appConfigService);
  }

  it('retries timeout errors and succeeds', async () => {
    const fetchMock = jest
      .fn()
      .mockRejectedValueOnce(new Error('timeout'))
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ result: 'PONG' }),
      } as Response);
    global.fetch = fetchMock as typeof fetch;

    const service = createService({ retryAttempts: 1 });
    await expect(service.ping()).resolves.toBe('PONG');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('does not retry non-retryable client errors', async () => {
    const fetchMock = jest.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: () => Promise.resolve({ error: 'unauthorized' }),
    } as Response);
    global.fetch = fetchMock as typeof fetch;

    const service = createService({ retryAttempts: 3 });
    await expect(service.ping()).rejects.toThrow('unauthorized');
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});
