import { ArgumentsHost, Catch, HttpException } from '@nestjs/common';
import { BaseExceptionFilter } from '@nestjs/core';
import { captureError } from './sentry';

/**
 * Le filtre global : une exception INATTENDUE (jamais un refus HTTP délibéré
 * — 4xx/403/404 sont des verdicts, pas des défaillances) part vers
 * l'observabilité, PUIS la réponse standard suit (500 sans corps parlant).
 * Le scrubbing vit dans sentry.ts : ici on ne décide que QUOI capturer.
 */
@Catch()
export class ObservabilityExceptionFilter extends BaseExceptionFilter {
  override catch(exception: unknown, host: ArgumentsHost): void {
    if (!(exception instanceof HttpException)) {
      captureError(exception);
    }
    super.catch(exception, host);
  }
}
