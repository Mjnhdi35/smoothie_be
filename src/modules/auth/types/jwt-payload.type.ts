export interface JwtPayload {
  sub: string;
  jti: string;
  fp: string;
  type: 'access' | 'refresh';
  iat: number;
  exp: number;
}
