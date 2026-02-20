import { Module } from '@nestjs/common';
import { AuditLogRepository } from './repositories/audit-log.repository';
import { UsersRepository } from './repositories/users.repository';
import { UsersService } from './users.service';

@Module({
  providers: [UsersRepository, AuditLogRepository, UsersService],
  exports: [UsersService],
})
export class UsersModule {}
