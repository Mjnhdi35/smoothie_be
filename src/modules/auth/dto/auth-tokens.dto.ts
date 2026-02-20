export class AuthTokensDto {
  accessToken!: string;
  refreshToken!: string;
  tokenType!: 'Bearer';
  expiresIn!: number;
}
