import { Test, TestingModule } from '@nestjs/testing';
import { AppController } from './app.controller';

describe('AppController', () => {
  let appController: AppController;

  beforeEach(async () => {
    const app: TestingModule = await Test.createTestingModule({
      controllers: [AppController],
    }).compile();

    appController = app.get<AppController>(AppController);
  });

  describe('health', () => {
    it('should return health payload', () => {
      const response = appController.getHealth();
      expect(response.ok).toBe(true);
      expect(typeof response.timestamp).toBe('string');
    });
  });
});
