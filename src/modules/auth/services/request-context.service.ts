import { Injectable } from '@nestjs/common';
import type { Request } from 'express';
import { sha256 } from '../../../common/utils/crypto.util';

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

  computeFingerprint(request: Request, secret: string): string {
    return sha256(
      `${secret}|${this.getIp(request)}|${this.getUserAgent(request)}`,
    );
  }
}
