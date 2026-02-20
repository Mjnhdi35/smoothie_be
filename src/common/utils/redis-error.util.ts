export function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function isRedisOperationalError(error: unknown): boolean {
  const message = getErrorMessage(error).toLowerCase();
  return (
    message.includes('noperm') ||
    message.includes('noauth') ||
    message.includes('no permissions') ||
    message.includes('authentication required') ||
    message.includes('timeout') ||
    message.includes('fetch failed') ||
    message.includes('upstash') ||
    message.includes('timed out') ||
    message.includes('econnrefused') ||
    message.includes('etimedout') ||
    message.includes('eai_again')
  );
}
