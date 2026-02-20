import type { Request } from 'express';
import { RequestContextService } from './request-context.service';

describe('RequestContextService', () => {
  const service = new RequestContextService();

  it('extracts ip and user-agent defaults', () => {
    const request = { headers: {} } as Request;

    expect(service.getIp(request)).toBe('unknown');
    expect(service.getUserAgent(request)).toBe('unknown');
  });

  it('builds audit context and fingerprint', () => {
    const request = {
      ip: '127.0.0.1',
      headers: { 'user-agent': 'jest-agent' },
    } as unknown as Request;

    const context = service.getAuditContext(request);
    expect(context).toEqual({ ip: '127.0.0.1', userAgent: 'jest-agent' });
    expect(service.computeFingerprint(request, 'secret-1')).not.toBe(
      service.computeFingerprint(request, 'secret-2'),
    );
  });
});
