import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { AppController } from '../src/app.controller';
import { HealthService } from '../src/common/services/health.service';

describe('AppController (e2e)', () => {
  let app: INestApplication;
  let controller: AppController;
  const healthService = {
    liveness: jest.fn(() => ({
      ok: true,
      timestamp: new Date().toISOString(),
    })),
    readiness: jest.fn(),
  } as unknown as HealthService;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      controllers: [AppController],
      providers: [{ provide: HealthService, useValue: healthService }],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
    controller = app.get(AppController);
  });

  afterEach(async () => {
    if (app) {
      await app.close();
    }
  });

  it('/health (GET)', () => {
    const body = controller.getHealth();
    expect(body.ok).toBe(true);
    expect(typeof body.timestamp).toBe('string');
  });
});
