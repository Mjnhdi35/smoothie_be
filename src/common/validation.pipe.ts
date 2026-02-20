import { ValidationPipe } from '@nestjs/common';

export const strictValidationPipe = new ValidationPipe({
  whitelist: true,
  forbidNonWhitelisted: true,
  transform: true,
  transformOptions: {
    enableImplicitConversion: false,
  },
  validationError: {
    target: false,
    value: false,
  },
});
