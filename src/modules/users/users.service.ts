import { Inject, Injectable } from '@nestjs/common';
import { Knex } from 'knex';
import { KNEX_CONNECTION } from '../../infrastructure/database/database.constants';
import { AuditLogRepository } from './repositories/audit-log.repository';
import { UsersRepository } from './repositories/users.repository';
import type { UserEntity } from './entities/user.entity';

@Injectable()
export class UsersService {
  constructor(
    @Inject(KNEX_CONNECTION) private readonly db: Knex,
    private readonly usersRepository: UsersRepository,
    private readonly auditLogRepository: AuditLogRepository,
  ) {}

  async findByEmail(email: string): Promise<UserEntity | null> {
    return this.usersRepository.findByEmail(email);
  }

  async findById(id: string): Promise<UserEntity | null> {
    return this.usersRepository.findById(id);
  }

  async createUserWithAudit(params: {
    email: string;
    passwordHash: string;
    ip: string | null;
    userAgent: string | null;
  }): Promise<UserEntity> {
    return this.db.transaction(async (trx: Knex.Transaction) => {
      const user = await this.usersRepository.createUser({
        email: params.email,
        passwordHash: params.passwordHash,
        trx,
      });

      await this.auditLogRepository.create({
        userId: user.id,
        event: 'auth.register',
        ip: params.ip,
        userAgent: params.userAgent,
        metadata: { email: user.email },
        trx,
      });

      return user;
    });
  }

  async writeAudit(params: {
    userId: string | null;
    event: string;
    ip: string | null;
    userAgent: string | null;
    metadata?: Record<string, unknown>;
  }): Promise<void> {
    await this.auditLogRepository.create(params);
  }
}
