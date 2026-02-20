import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { LoggerModule } from 'nestjs-pino';
import { randomUUID } from 'node:crypto';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AppConfigService } from './config/app-config.service';
import { AppConfigModule } from './config/config.module';
import { validateEnv } from './config/env.validation';
import { DatabaseModule } from './infrastructure/database/database.module';
import { RedisModule } from './infrastructure/redis/redis.module';
import { AuthModule } from './modules/auth/auth.module';
import { UsersModule } from './modules/users/users.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validate: validateEnv,
      cache: true,
      expandVariables: true,
    }),
    AppConfigModule,
    LoggerModule.forRootAsync({
      inject: [ConfigService, AppConfigService],
      useFactory: (
        configService: ConfigService,
        appConfigService: AppConfigService,
      ) => ({
        pinoHttp: {
          messageKey: 'message',
          level: appConfigService.pinoLevel,
          timestamp: () => `,"time":"${new Date().toISOString()}"`,
          redact: ['req.headers.authorization'],
          customProps: (req: { id?: unknown }) => ({
            reqId:
              typeof req.id === 'string' || typeof req.id === 'number'
                ? String(req.id)
                : undefined,
          }),
          autoLogging: {
            ignore: (req: { url?: string }) => req.url === '/health',
          },
          genReqId: (req: { headers: Record<string, unknown> }) => {
            const fromHeader = req.headers['x-request-id'];
            return typeof fromHeader === 'string' && fromHeader.length > 0
              ? fromHeader
              : randomUUID();
          },
          transport:
            appConfigService.nodeEnv === 'development'
              ? {
                  target: 'pino-pretty',
                  options: {
                    colorize: true,
                    singleLine: true,
                    translateTime: 'SYS:standard',
                    ignore: 'pid,hostname,req,res,responseTime',
                    messageFormat:
                      '[{reqId}] {req.method} {req.url} -> {res.statusCode} ({responseTime}ms)',
                  },
                }
              : undefined,
        },
      }),
    }),
    DatabaseModule,
    RedisModule,
    UsersModule,
    AuthModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
