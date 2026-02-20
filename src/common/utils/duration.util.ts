const DURATION_REGEX = /^(\d+)([smhd])$/;

const MULTIPLIER: Record<string, number> = {
  s: 1,
  m: 60,
  h: 60 * 60,
  d: 60 * 60 * 24,
};

export function durationToSeconds(duration: string): number {
  const trimmed = duration.trim();
  const match = DURATION_REGEX.exec(trimmed);

  if (!match) {
    throw new Error(`Invalid duration format: ${duration}`);
  }

  const [, value, unit] = match;
  return Number(value) * MULTIPLIER[unit];
}
