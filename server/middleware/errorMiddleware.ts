import type { NextFunction, Request, Response } from "express";
import { logger } from "../lib/logger";
import { AppError, isAppError } from "../lib/errors";

export interface ErrorResponseBody {
  error: {
    code: string;
    message: string;
    details?: unknown;
  };
}

export const errorMiddleware = (
  err: unknown,
  _req: Request,
  res: Response<ErrorResponseBody>,
  _next: NextFunction,
) => {
  const appError = isAppError(err)
    ? err
    : new AppError((err as Error)?.message ?? "Internal Server Error", { code: "INTERNAL_ERROR" });

  const statusCode = appError.statusCode ?? 500;

  logger.error(
    {
      err,
      statusCode,
      code: appError.code,
    },
    appError.message,
  );

  res.status(statusCode).json({
    error: {
      code: appError.code,
      message: appError.message,
      details: appError.details,
    },
  });
};
