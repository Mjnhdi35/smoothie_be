import { sha256 } from '../../../common/utils/crypto.util';

export function refreshSessionKey(jti: string): string {
  return `auth:refresh:${jti}`;
}

export function usedRefreshSessionKey(jti: string): string {
  return `auth:refresh:used:${jti}`;
}

export function userRefreshSessionsKey(userId: string): string {
  return `auth:user_refresh:${userId}`;
}

export function bruteForceIpKey(ip: string): string {
  return `auth:bruteforce:ip:${sha256(ip)}`;
}

export function bruteForceEmailKey(email: string): string {
  return `auth:bruteforce:email:${sha256(email.toLowerCase())}`;
}
