import { Controller, Get } from '@nestjs/common';

@Controller()
export class AppController {
  @Get('health')
  getHealth(): { ok: true; timestamp: string } {
    return {
      ok: true,
      timestamp: new Date().toISOString(),
    };
  }
}
