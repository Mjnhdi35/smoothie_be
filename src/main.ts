import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import helmet from 'helmet';
import { Logger as PinoLogger } from 'nestjs-pino';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { strictValidationPipe } from './common/validation.pipe';
import { AppConfigService } from './config/app-config.service';
import { AppModule } from './app.module';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    bufferLogs: true,
  });

  const appConfigService = app.get(AppConfigService);
  const logger = app.get(PinoLogger);

  app.useLogger(logger);

  if (appConfigService.trustProxy) {
    app.set('trust proxy', 1);
  }

  app.use(helmet());

  app.enableCors({
    origin: appConfigService.corsOrigins,
    methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
    credentials: true,
  });

  app.useGlobalPipes(strictValidationPipe);
  app.useGlobalFilters(new HttpExceptionFilter());
  app.enableShutdownHooks();

  await app.listen(appConfigService.port, '0.0.0.0');

  logger.log(`API started on port ${appConfigService.port}`);
}

void bootstrap();
