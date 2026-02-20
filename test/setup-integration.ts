import { randomUUID } from 'node:crypto';

function setDefaultEnv(key: string, value: string): void {
  if (!process.env[key] || process.env[key]?.trim().length === 0) {
    process.env[key] = value;
  }
}

const accessSecret = randomUUID();
const refreshSecret = randomUUID();

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

setDefaultEnv('JWT_ACCESS_SECRET', accessSecret);
setDefaultEnv('JWT_REFRESH_SECRET', refreshSecret);
setDefaultEnv('JWT_ACCESS_EXPIRES_IN', '15m');
setDefaultEnv('JWT_REFRESH_EXPIRES_IN', '7d');

setDefaultEnv('LOGIN_RATE_LIMIT_MAX_ATTEMPTS', '5');
setDefaultEnv('LOGIN_RATE_LIMIT_WINDOW_SECONDS', '900');
