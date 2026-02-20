export const AUTH_MESSAGES = {
  INVALID_CREDENTIALS: 'Invalid credentials',
  INVALID_REFRESH_TOKEN: 'Refresh token is not valid',
  REFRESH_TOKEN_REUSE: 'Refresh token reuse detected',
  SERVICE_UNAVAILABLE: 'Authentication service is temporarily unavailable',
} as const;

export const AUTH_EVENTS = {
  LOGIN_FAILED: 'auth.login_failed',
  LOGIN_SUCCESS: 'auth.login_success',
  REFRESH_SUCCESS: 'auth.refresh_success',
  REFRESH_REUSE_DETECTED: 'auth.refresh_reuse_detected',
  LOGOUT: 'auth.logout',
} as const;
