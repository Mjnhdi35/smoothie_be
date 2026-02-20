const BASE_REQUIRED_ENV_KEYS = [
  'NODE_ENV',
  'PORT',
  'CORS_ORIGIN',
  'TRUST_PROXY',
  'REDIS_HOST',
  'REDIS_PORT',
  'REDIS_USERNAME',
  'REDIS_PASSWORD',
  'REDIS_TLS',
  'JWT_ACCESS_PRIVATE_KEY',
  'JWT_ACCESS_PUBLIC_KEY',
  'JWT_REFRESH_PRIVATE_KEY',
  'JWT_REFRESH_PUBLIC_KEY',
  'JWT_ACCESS_EXPIRES_IN',
  'JWT_REFRESH_EXPIRES_IN',
  'JWT_FINGERPRINT_SECRET',
  'LOGIN_RATE_LIMIT_MAX_ATTEMPTS',
  'LOGIN_RATE_LIMIT_WINDOW_SECONDS',
  'PINO_LEVEL',
] as const;

const POSTGRES_COMPONENT_KEYS = [
  'POSTGRES_HOST',
  'POSTGRES_PORT',
  'POSTGRES_DB',
  'POSTGRES_USER',
  'POSTGRES_PASSWORD',
  'POSTGRES_SSL',
] as const;

export type EnvShape = Record<string, string>;

function isBooleanString(value: string): boolean {
  return value === 'true' || value === 'false';
}

export function validateEnv(config: Record<string, unknown>): EnvShape {
  const missingKeys: string[] = BASE_REQUIRED_ENV_KEYS.filter((key) => {
    const value = config[key];
    return typeof value !== 'string' || value.trim().length === 0;
  });

  const hasDatabaseUrl =
    typeof config.DATABASE_URL === 'string' &&
    config.DATABASE_URL.trim().length > 0;

  if (!hasDatabaseUrl) {
    const missingPostgresKeys = POSTGRES_COMPONENT_KEYS.filter((key) => {
      const value = config[key];
      return typeof value !== 'string' || value.trim().length === 0;
    });
    missingKeys.push(...missingPostgresKeys);
  }

  if (missingKeys.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missingKeys.join(', ')}`,
    );
  }

  const integerKeys = [
    'PORT',
    'REDIS_PORT',
    'LOGIN_RATE_LIMIT_MAX_ATTEMPTS',
    'LOGIN_RATE_LIMIT_WINDOW_SECONDS',
  ];
  if (!hasDatabaseUrl) {
    integerKeys.push('POSTGRES_PORT');
  }

  for (const key of integerKeys) {
    const value = Number(config[key]);
    if (!Number.isInteger(value) || value <= 0) {
      throw new Error(`${key} must be a positive integer`);
    }
  }

  const booleanKeys = ['TRUST_PROXY', 'REDIS_TLS'];
  if (!hasDatabaseUrl) {
    booleanKeys.push('POSTGRES_SSL');
  }

  for (const key of booleanKeys) {
    const value = String(config[key]);
    if (!isBooleanString(value)) {
      throw new Error(`${key} must be either "true" or "false"`);
    }
  }

  const pinoLevel = String(config.PINO_LEVEL);
  if (
    !['fatal', 'error', 'warn', 'info', 'debug', 'trace'].includes(pinoLevel)
  ) {
    throw new Error(
      'PINO_LEVEL must be one of fatal,error,warn,info,debug,trace',
    );
  }

  const normalized: EnvShape = {};
  for (const [key, value] of Object.entries(config)) {
    if (typeof value === 'string') {
      normalized[key] = value;
    }
  }

  return normalized;
}
