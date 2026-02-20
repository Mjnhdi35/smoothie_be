import { HealthService } from './health.service';

describe('HealthService', () => {
  const raw = jest.fn();
  const db = { raw };

  const ping = jest.fn();
  const redisService = { ping };

  const service = new HealthService(db as never, redisService as never);

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns liveness payload', () => {
    const payload = service.liveness();
    expect(payload.ok).toBe(true);
    expect(typeof payload.timestamp).toBe('string');
  });

  it('returns readiness when db and redis are available', async () => {
    raw.mockResolvedValue([{ ok: 1 }]);
    ping.mockResolvedValue('PONG');

    await expect(service.readiness()).resolves.toMatchObject({
      ok: true,
      checks: {
        database: 'up',
        redis: 'up',
      },
    });
  });

  it('throws when redis is unavailable', async () => {
    raw.mockResolvedValue([{ ok: 1 }]);
    ping.mockRejectedValue(new Error('upstash timeout'));

    await expect(service.readiness()).rejects.toThrow('upstash timeout');
  });
});
