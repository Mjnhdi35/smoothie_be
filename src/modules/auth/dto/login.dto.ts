import {
  IsEmail,
  IsIn,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
  ValidateIf,
} from 'class-validator';
import type { AuthProvider } from '../types/auth-provider.type';

export class LoginDto {
  @IsOptional()
  @IsIn(['password', 'google'])
  provider?: AuthProvider;

  @ValidateIf((o: LoginDto) => !o.provider || o.provider === 'password')
  @IsEmail()
  email?: string;

  @ValidateIf((o: LoginDto) => !o.provider || o.provider === 'password')
  @IsString()
  @MinLength(12)
  @MaxLength(128)
  password?: string;

  @ValidateIf((o: LoginDto) => o.provider === 'google')
  @IsString()
  @MinLength(20)
  googleIdToken?: string;
}
