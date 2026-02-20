const BASE_REQUIRED_ENV_KEYS = [
  'NODE_ENV',
  'PORT',
  'CORS_ORIGIN',
  'JWT_ACCESS_SECRET',
  'JWT_REFRESH_SECRET',
  'JWT_ACCESS_EXPIRES_IN',
  'JWT_REFRESH_EXPIRES_IN',
] as const;

const POSTGRES_COMPONENT_KEYS = [
  'POSTGRES_HOST',
  'POSTGRES_PORT',
  'POSTGRES_DB',
  'POSTGRES_USER',
  'POSTGRES_PASSWORD',
  'POSTGRES_SSL',
] as const;
const PINO_LEVELS = [
  'fatal',
  'error',
  'warn',
  'info',
  'debug',
  'trace',
] as const;

export type EnvShape = Record<string, string>;

function hasString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

function isBooleanString(value: string): boolean {
  return value === 'true' || value === 'false';
}

export function validateEnv(config: Record<string, unknown>): EnvShape {
  const missingKeys: string[] = BASE_REQUIRED_ENV_KEYS.filter(
    (key) => !hasString(config[key]),
  );

  const databaseUrl = hasString(config.DATABASE_URL)
    ? config.DATABASE_URL
    : undefined;
  const upstashRedisRestUrl = hasString(config.UPSTASH_REDIS_REST_URL)
    ? config.UPSTASH_REDIS_REST_URL
    : undefined;
  const upstashRedisRestToken = hasString(config.UPSTASH_REDIS_REST_TOKEN)
    ? config.UPSTASH_REDIS_REST_TOKEN
    : undefined;

  if (databaseUrl) {
    if (
      !databaseUrl.startsWith('postgres://') &&
      !databaseUrl.startsWith('postgresql://')
    ) {
      throw new Error(
        'DATABASE_URL must start with postgres:// or postgresql://',
      );
    }
  } else {
    missingKeys.push(
      ...POSTGRES_COMPONENT_KEYS.filter((key) => !hasString(config[key])),
    );
  }

  if (!upstashRedisRestUrl) {
    missingKeys.push('UPSTASH_REDIS_REST_URL');
  } else if (
    !upstashRedisRestUrl.startsWith('https://') &&
    !upstashRedisRestUrl.startsWith('http://')
  ) {
    throw new Error(
      'UPSTASH_REDIS_REST_URL must start with https:// or http://',
    );
  } else if (upstashRedisRestUrl.includes(':6379')) {
    throw new Error(
      'UPSTASH_REDIS_REST_URL looks like TCP endpoint (:6379). Use Upstash REST URL from dashboard, not rediss host.',
    );
  }

  if (!upstashRedisRestToken) {
    missingKeys.push('UPSTASH_REDIS_REST_TOKEN');
  }

  if (missingKeys.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missingKeys.join(', ')}`,
    );
  }

  const integerKeys = ['PORT'];
  if (!databaseUrl) {
    integerKeys.push('POSTGRES_PORT');
  }

  for (const key of integerKeys) {
    const value = Number(config[key]);
    if (!Number.isInteger(value) || value <= 0) {
      throw new Error(`${key} must be a positive integer`);
    }
  }

  for (const key of [
    'LOGIN_RATE_LIMIT_MAX_ATTEMPTS',
    'LOGIN_RATE_LIMIT_WINDOW_SECONDS',
    'BCRYPT_SALT_ROUNDS',
    'REDIS_TIMEOUT_MS',
  ]) {
    if (!hasString(config[key])) {
      continue;
    }
    const value = Number(config[key]);
    if (!Number.isInteger(value) || value <= 0) {
      throw new Error(`${key} must be a positive integer`);
    }
  }

  for (const key of ['REDIS_RETRY_ATTEMPTS', 'REDIS_RETRY_DELAY_MS']) {
    if (!hasString(config[key])) {
      continue;
    }
    const value = Number(config[key]);
    if (!Number.isInteger(value) || value < 0) {
      throw new Error(`${key} must be a non-negative integer`);
    }
  }

  if (!databaseUrl && !isBooleanString(String(config.POSTGRES_SSL))) {
    throw new Error('POSTGRES_SSL must be either "true" or "false"');
  }
  if (hasString(config.TRUST_PROXY) && !isBooleanString(config.TRUST_PROXY)) {
    throw new Error('TRUST_PROXY must be either "true" or "false"');
  }
  if (hasString(config.PINO_PRETTY) && !isBooleanString(config.PINO_PRETTY)) {
    throw new Error('PINO_PRETTY must be either "true" or "false"');
  }

  if (
    hasString(config.PINO_LEVEL) &&
    !PINO_LEVELS.includes(config.PINO_LEVEL as (typeof PINO_LEVELS)[number])
  ) {
    throw new Error(`PINO_LEVEL must be one of ${PINO_LEVELS.join(',')}`);
  }

  const normalized: EnvShape = {};
  for (const [key, value] of Object.entries(config)) {
    if (typeof value === 'string') {
      normalized[key] = value;
    }
  }

  return normalized;
}
