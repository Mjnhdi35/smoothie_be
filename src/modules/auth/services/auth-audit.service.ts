import { Injectable } from '@nestjs/common';
import type { Request } from 'express';
import { UsersService } from '../../users/users.service';
import { RequestContextService } from './request-context.service';

@Injectable()
export class AuthAuditService {
  constructor(
    private readonly usersService: UsersService,
    private readonly requestContextService: RequestContextService,
  ) {}

  async write(params: {
    request: Request;
    userId: string | null;
    event: string;
    metadata?: Record<string, unknown>;
  }): Promise<void> {
    await this.usersService.writeAudit({
      ...this.requestContextService.getAuditContext(params.request),
      userId: params.userId,
      event: params.event,
      metadata: params.metadata,
    });
  }
}
