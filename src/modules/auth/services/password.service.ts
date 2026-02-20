import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

@Injectable()
export class PasswordService {
  private static readonly SALT_ROUNDS = 12;
  private static readonly FALLBACK_HASH =
    '$2b$12$XSLWPuyQyBrjlBSs9ez8sOJX2fAByLhNfYcUfhziD3SxQjAFN9bBa';

  normalizeEmail(email: string): string {
    return email.trim().toLowerCase();
  }

  hash(password: string): Promise<string> {
    return bcrypt.hash(password, PasswordService.SALT_ROUNDS);
  }

  async verify(
    storedHash: string | undefined,
    password: string,
  ): Promise<boolean> {
    const hash = storedHash ?? PasswordService.FALLBACK_HASH;
    return bcrypt.compare(password, hash).catch(() => false);
  }
}
