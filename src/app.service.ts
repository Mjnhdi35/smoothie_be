import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHealth(): { ok: true; timestamp: string } {
    return {
      ok: true,
      timestamp: new Date().toISOString(),
    };
  }
}
