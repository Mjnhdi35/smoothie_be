import { ConflictException, Inject, Injectable } from '@nestjs/common';
import { Knex } from 'knex';
import { KNEX_CONNECTION } from '../../../infrastructure/database/database.constants';
import type { UserEntity } from '../entities/user.entity';

interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  created_at: Date;
  updated_at: Date;
}

@Injectable()
export class UsersRepository {
  constructor(@Inject(KNEX_CONNECTION) private readonly db: Knex) {}

  async findByEmail(email: string): Promise<UserEntity | null> {
    const row = await this.db<UserRow>('users').where({ email }).first();
    return row ? this.mapToEntity(row) : null;
  }

  async findById(id: string): Promise<UserEntity | null> {
    const row = await this.db<UserRow>('users').where({ id }).first();
    return row ? this.mapToEntity(row) : null;
  }

  async deleteById(id: string): Promise<void> {
    await this.db<UserRow>('users').where({ id }).del();
  }

  async createUser(params: {
    email: string;
    passwordHash: string;
    trx?: Knex.Transaction;
  }): Promise<UserEntity> {
    const { email, passwordHash, trx } = params;
    const query = (trx ?? this.db)<UserRow>('users');

    try {
      const [row] = await query
        .insert({
          email,
          password_hash: passwordHash,
        })
        .returning('*');

      return this.mapToEntity(row);
    } catch (error: unknown) {
      if (
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        error.code === '23505'
      ) {
        throw new ConflictException('Email is already registered');
      }

      throw error;
    }
  }

  private mapToEntity(row: UserRow): UserEntity {
    return {
      id: row.id,
      email: row.email,
      passwordHash: row.password_hash,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
