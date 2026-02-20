export interface JwtPayload {
  sub: string;
  jti: string;
  type: 'access' | 'refresh';
  iat: number;
  exp: number;
}
