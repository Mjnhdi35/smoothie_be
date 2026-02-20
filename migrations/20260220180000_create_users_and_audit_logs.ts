import type { Knex } from 'knex';

export async function up(knex: Knex): Promise<void> {
  await knex.raw('CREATE EXTENSION IF NOT EXISTS "pgcrypto"');

  await knex.schema.createTable('users', (table: Knex.CreateTableBuilder) => {
    table.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'));
    table.string('email', 320).notNullable();
    table.text('password_hash').notNullable();
    table
      .timestamp('created_at', { useTz: true })
      .notNullable()
      .defaultTo(knex.fn.now());
    table
      .timestamp('updated_at', { useTz: true })
      .notNullable()
      .defaultTo(knex.fn.now());

    table.unique(['email'], {
      indexName: 'users_email_unique',
    });
    table.index(['email'], 'users_email_idx');
  });

  await knex.schema.createTable(
    'audit_logs',
    (table: Knex.CreateTableBuilder) => {
      table.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'));
      table
        .uuid('user_id')
        .nullable()
        .references('id')
        .inTable('users')
        .onDelete('SET NULL');
      table.string('event', 120).notNullable();
      table.specificType('ip', 'inet').nullable();
      table.text('user_agent').nullable();
      table.jsonb('metadata').notNullable().defaultTo('{}');
      table
        .timestamp('created_at', { useTz: true })
        .notNullable()
        .defaultTo(knex.fn.now());

      table.index(['user_id'], 'audit_logs_user_id_idx');
      table.index(['event'], 'audit_logs_event_idx');
      table.index(['created_at'], 'audit_logs_created_at_idx');
    },
  );
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists('audit_logs');
  await knex.schema.dropTableIfExists('users');
}
