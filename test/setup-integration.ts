import { generateKeyPairSync } from 'node:crypto';

function setDefaultEnv(key: string, value: string): void {
  if (!process.env[key] || process.env[key]?.trim().length === 0) {
    process.env[key] = value;
  }
}

const accessKeyPair = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const refreshKeyPair = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

setDefaultEnv('NODE_ENV', 'test');
setDefaultEnv('PORT', '3001');
setDefaultEnv('CORS_ORIGIN', 'http://localhost:3001');
setDefaultEnv('TRUST_PROXY', 'false');
setDefaultEnv('PINO_LEVEL', 'error');

setDefaultEnv(
  'DATABASE_URL',
  'postgresql://smoothie_user:smoothie_pass@127.0.0.1:5432/smoothie_db?sslmode=disable',
);

setDefaultEnv('REDIS_HOST', '127.0.0.1');
setDefaultEnv('REDIS_PORT', '6379');
setDefaultEnv('REDIS_USERNAME', 'default');
setDefaultEnv('REDIS_PASSWORD', 'smoothie_redis_pass');
setDefaultEnv('REDIS_TLS', 'false');

setDefaultEnv('JWT_ACCESS_PRIVATE_KEY', accessKeyPair.privateKey);
setDefaultEnv('JWT_ACCESS_PUBLIC_KEY', accessKeyPair.publicKey);
setDefaultEnv('JWT_REFRESH_PRIVATE_KEY', refreshKeyPair.privateKey);
setDefaultEnv('JWT_REFRESH_PUBLIC_KEY', refreshKeyPair.publicKey);
setDefaultEnv('JWT_ACCESS_EXPIRES_IN', '15m');
setDefaultEnv('JWT_REFRESH_EXPIRES_IN', '7d');
setDefaultEnv('JWT_FINGERPRINT_SECRET', 'integration-test-fingerprint-secret');

setDefaultEnv('LOGIN_RATE_LIMIT_MAX_ATTEMPTS', '5');
setDefaultEnv('LOGIN_RATE_LIMIT_WINDOW_SECONDS', '900');
