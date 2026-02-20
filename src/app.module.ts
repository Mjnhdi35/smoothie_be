import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { LoggerModule } from 'nestjs-pino';
import { randomUUID } from 'node:crypto';
import { AppController } from './app.controller';
import { ResponseTimeInterceptor } from './common/interceptors/response-time.interceptor';
import { RequestIdMiddleware } from './common/middlewares/request-id.middleware';
import { HealthService } from './common/services/health.service';
import { AppConfigService } from './config/app-config.service';
import { AppConfigModule } from './config/config.module';
import { validateEnv } from './config/env.validation';
import { DatabaseModule } from './infrastructure/database/database.module';
import { RedisModule } from './infrastructure/redis/redis.module';
import { AuthModule } from './modules/auth/auth.module';
import { UsersModule } from './modules/users/users.module';

function resolvePrettyTransport():
  | {
      target: string;
      options: {
        colorize: boolean;
        singleLine: boolean;
        translateTime: string;
        ignore: string;
        messageFormat: string;
      };
    }
  | undefined {
  try {
    require.resolve('pino-pretty');
  } catch {
    return undefined;
  }

  return {
    target: 'pino-pretty',
    options: {
      colorize: true,
      singleLine: true,
      translateTime: 'SYS:standard',
      ignore: 'pid,hostname,req,res,responseTime',
      messageFormat:
        '[{reqId}] {req.method} {req.url} -> {res.statusCode} ({responseTime}ms)',
    },
  };
}

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
      inject: [AppConfigService],
      useFactory: (appConfigService: AppConfigService) => ({
        pinoHttp: {
          messageKey: 'message',
          level: appConfigService.pinoLevel,
          timestamp: () => `,"time":"${new Date().toISOString()}"`,
          redact: [
            'req.headers.authorization',
            'req.headers.cookie',
            'res.headers["set-cookie"]',
            'req.body.password',
            'req.body.refreshToken',
          ],
          customProps: (req: { id?: unknown }) => ({
            reqId:
              typeof req.id === 'string' || typeof req.id === 'number'
                ? String(req.id)
                : undefined,
          }),
          autoLogging: {
            ignore: (req: { url?: string; method?: string }) =>
              req.url === '/health' ||
              req.url === '/health/ready' ||
              ((req.url === '/' ||
                req.url === '/health' ||
                req.url === '/health/ready') &&
                req.method === 'HEAD'),
          },
          customSuccessMessage: (
            req: { method?: string; url?: string },
            res: { statusCode?: number },
            responseTime: number,
          ) =>
            `${req.method ?? 'UNKNOWN'} ${req.url ?? 'unknown'} -> ${res.statusCode ?? 0} (${responseTime}ms)`,
          customErrorMessage: (
            req: { method?: string; url?: string },
            res: { statusCode?: number },
            error: Error,
          ) =>
            `${req.method ?? 'UNKNOWN'} ${req.url ?? 'unknown'} -> ${res.statusCode ?? 0} failed: ${error.message}`,
          genReqId: (req: { headers: Record<string, unknown> }) => {
            const fromHeader = req.headers['x-request-id'];
            return typeof fromHeader === 'string' && fromHeader.length > 0
              ? fromHeader
              : randomUUID();
          },
          transport: appConfigService.pinoPretty
            ? resolvePrettyTransport()
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
  providers: [
    HealthService,
    {
      provide: APP_INTERCEPTOR,
      useClass: ResponseTimeInterceptor,
    },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(RequestIdMiddleware).forRoutes('*');
  }
}
