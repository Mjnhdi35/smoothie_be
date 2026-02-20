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
        const { url, host, port, database, user, password, ssl } =
          appConfig.postgres;

        return knex({
          client: 'pg',
          connection: url
            ? url
            : {
                host,
                port,
                database,
                user,
                password,
                ssl: ssl ? { rejectUnauthorized: true } : false,
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
