import { ExecutionContext, HttpStatus } from '@nestjs/common';
import { AppConfigService } from '../../config/app-config.service';
import { RedisService } from '../../infrastructure/redis/redis.service';
import { LoginRateLimitGuard } from './login-rate-limit.guard';

function makeExecutionContext(request: unknown): ExecutionContext {
  return {
    switchToHttp: () => ({
      getRequest: () => request,
    }),
  } as unknown as ExecutionContext;
}

describe('LoginRateLimitGuard', () => {
  const incr = jest.fn();
  const expire = jest.fn();

  const redisService = {
    client: {
      incr,
      expire,
    },
  } as unknown as RedisService;

  const appConfigService = {
    loginRateLimit: {
      maxAttempts: 5,
      windowSeconds: 900,
    },
  } as AppConfigService;

  const guard = new LoginRateLimitGuard(redisService, appConfigService);

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('allows request under limit', async () => {
    incr.mockResolvedValueOnce(1).mockResolvedValueOnce(1);
    expire.mockResolvedValue(undefined);

    await expect(
      guard.canActivate(
        makeExecutionContext({
          ip: '127.0.0.1',
          body: { email: 'alice@example.com' },
        }),
      ),
    ).resolves.toBe(true);
  });

  it('blocks request over limit', async () => {
    incr.mockResolvedValueOnce(6).mockResolvedValueOnce(2);
    expire.mockResolvedValue(undefined);

    await expect(
      guard.canActivate(
        makeExecutionContext({
          ip: '127.0.0.1',
          body: { email: 'alice@example.com' },
        }),
      ),
    ).rejects.toMatchObject({
      status: HttpStatus.TOO_MANY_REQUESTS,
      message: 'Too many login attempts',
    });
  });
});
