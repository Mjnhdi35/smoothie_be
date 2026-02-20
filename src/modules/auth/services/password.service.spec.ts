import { PasswordService } from './password.service';

describe('PasswordService', () => {
  const service = new PasswordService();

  it('normalizes email', () => {
    expect(service.normalizeEmail('  Alice@Example.COM ')).toBe(
      'alice@example.com',
    );
  });

  it('hashes and verifies password', async () => {
    const password = 'SuperStrongPass123!';
    const hash = await service.hash(password);

    await expect(service.verify(hash, password)).resolves.toBe(true);
    await expect(service.verify(hash, 'wrong-password')).resolves.toBe(false);
  });
});
