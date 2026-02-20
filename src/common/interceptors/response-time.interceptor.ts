import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';

@Injectable()
export class ResponseTimeInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const response = context.switchToHttp().getResponse<{
      setHeader: (name: string, value: string) => void;
    }>();
    const startedAt = process.hrtime.bigint();

    return next.handle().pipe(
      tap(() => {
        const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
        response.setHeader('x-response-time', `${elapsedMs.toFixed(1)}ms`);
      }),
    );
  }
}
