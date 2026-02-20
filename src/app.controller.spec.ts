import { Test, TestingModule } from '@nestjs/testing';
import { AppController } from './app.controller';
import { HealthService } from './common/services/health.service';

describe('AppController', () => {
  let appController: AppController;
  const healthService = {
    liveness: jest.fn(),
    readiness: jest.fn(),
  } as unknown as HealthService;

  beforeEach(async () => {
    const app: TestingModule = await Test.createTestingModule({
      controllers: [AppController],
      providers: [{ provide: HealthService, useValue: healthService }],
    }).compile();

    appController = app.get<AppController>(AppController);
    jest.clearAllMocks();
  });

  describe('health', () => {
    it('should return health payload', () => {
      (healthService.liveness as jest.Mock).mockReturnValue({
        ok: true,
        timestamp: '2026-02-20T00:00:00.000Z',
      });

      const response = appController.getHealth();
      expect(response.ok).toBe(true);
      expect(typeof response.timestamp).toBe('string');
    });
  });
});
