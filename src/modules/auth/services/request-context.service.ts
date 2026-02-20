import { Injectable } from '@nestjs/common';
import type { Request } from 'express';

@Injectable()
export class RequestContextService {
  getIp(request: Request): string {
    return request.ip ?? 'unknown';
  }

  getUserAgent(request: Request): string {
    const userAgent = request.headers['user-agent'];
    return typeof userAgent === 'string' ? userAgent : 'unknown';
  }

  getAuditContext(request: Request): { ip: string; userAgent: string } {
    return {
      ip: this.getIp(request),
      userAgent: this.getUserAgent(request),
    };
  }
}
