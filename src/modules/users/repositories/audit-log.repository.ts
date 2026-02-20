import { Inject, Injectable } from '@nestjs/common';
import { Knex } from 'knex';
import { KNEX_CONNECTION } from '../../../infrastructure/database/database.constants';

@Injectable()
export class AuditLogRepository {
  constructor(@Inject(KNEX_CONNECTION) private readonly db: Knex) {}

  async create(params: {
    userId: string | null;
    event: string;
    ip: string | null;
    userAgent: string | null;
    metadata?: Record<string, unknown>;
    trx?: Knex.Transaction;
  }): Promise<void> {
    const query = (params.trx ?? this.db)('audit_logs');

    await query.insert({
      user_id: params.userId,
      event: params.event,
      ip: params.ip,
      user_agent: params.userAgent,
      metadata: params.metadata ?? {},
    });
  }
}
