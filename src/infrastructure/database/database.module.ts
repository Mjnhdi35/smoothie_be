import {
  Global,
  Inject,
  Injectable,
  Module,
  OnApplicationShutdown,
} from '@nestjs/common';
import { Knex, knex } from 'knex';
import { AppConfigService } from '../../config/app-config.service';
import { KNEX_CONNECTION } from './database.constants';

@Injectable()
class DatabaseLifecycle implements OnApplicationShutdown {
  constructor(@Inject(KNEX_CONNECTION) private readonly db: Knex) {}

  async onApplicationShutdown(): Promise<void> {
    await this.db.destroy();
  }
}

@Global()
@Module({
  providers: [
    {
      provide: KNEX_CONNECTION,
      inject: [AppConfigService],
      useFactory: (appConfig: AppConfigService): Knex => {
        const postgres = appConfig.postgres;

        return knex({
          client: 'pg',
          connection:
            'url' in postgres
              ? postgres.url
              : {
                  host: postgres.host,
                  port: postgres.port,
                  database: postgres.database,
                  user: postgres.user,
                  password: postgres.password,
                  ssl: postgres.ssl ? { rejectUnauthorized: true } : false,
                },
          pool: {
            min: 2,
            max: 20,
          },
        });
      },
    },
    DatabaseLifecycle,
  ],
  exports: [KNEX_CONNECTION],
})
export class DatabaseModule {}
