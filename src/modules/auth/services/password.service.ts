import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { AppConfigService } from '../../../config/app-config.service';

@Injectable()
export class PasswordService {
  private readonly saltRounds: number;

  constructor(appConfigService: AppConfigService) {
    this.saltRounds = appConfigService.password.saltRounds;
  }

  normalizeEmail(email: string): string {
    return email.trim().toLowerCase();
  }

  hash(password: string): Promise<string> {
    return bcrypt.hash(password, this.saltRounds);
  }

  async verify(
    storedHash: string | undefined,
    password: string,
  ): Promise<boolean> {
    if (!storedHash) {
      await bcrypt.hash(password, this.saltRounds);
      return false;
    }

    return bcrypt.compare(password, storedHash).catch(() => false);
  }
}
