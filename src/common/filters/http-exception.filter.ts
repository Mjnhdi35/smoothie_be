import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const context = host.switchToHttp();
    const response = context.getResponse<Response>();
    const request = context.getRequest<Request>();

    const httpException =
      exception instanceof HttpException ? exception : undefined;

    const status: HttpStatus = httpException
      ? (httpException.getStatus() as HttpStatus)
      : HttpStatus.INTERNAL_SERVER_ERROR;

    const exceptionResponse = httpException?.getResponse();

    const message =
      typeof exceptionResponse === 'object' &&
      exceptionResponse !== null &&
      'message' in exceptionResponse
        ? exceptionResponse.message
        : status === HttpStatus.INTERNAL_SERVER_ERROR
          ? 'Internal server error'
          : exception instanceof Error
            ? exception.message
            : 'Unexpected error';

    const isInternalError = status === HttpStatus.INTERNAL_SERVER_ERROR;
    const requestId =
      typeof request.id === 'string' || typeof request.id === 'number'
        ? String(request.id)
        : undefined;

    if (isInternalError && exception instanceof Error) {
      this.logger.error(
        `[${requestId ?? 'unknown'}] ${request.method} ${request.url} failed: ${exception.message}`,
        exception.stack,
      );
    } else if (isInternalError) {
      this.logger.error(
        `[${requestId ?? 'unknown'}] ${request.method} ${request.url} failed with non-Error exception`,
      );
    }

    response.status(status).json({
      statusCode: status,
      path: request.url,
      timestamp: new Date().toISOString(),
      message,
      requestId,
    });
  }
}
