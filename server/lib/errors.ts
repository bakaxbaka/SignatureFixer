import type { ZodIssue } from "zod";

export type ErrorCode =
  | "VALIDATION_ERROR"
  | "EXTERNAL_API_ERROR"
  | "INTERNAL_ERROR"
  | "RATE_LIMITED"
  | "NOT_FOUND";

export class AppError extends Error {
  public readonly statusCode: number;
  public readonly code: ErrorCode;
  public readonly details?: unknown;

  constructor(
    message: string,
    options: {
      statusCode?: number;
      code?: ErrorCode;
      details?: unknown;
      cause?: unknown;
    } = {},
  ) {
    super(message, { cause: options.cause });
    this.statusCode = options.statusCode ?? 500;
    this.code = options.code ?? "INTERNAL_ERROR";
    this.details = options.details;
  }
}

export const isAppError = (error: unknown): error is AppError => error instanceof Error && "statusCode" in error;

export const formatZodIssues = (issues: ZodIssue[]): string =>
  issues.map((issue) => `${issue.path.join(".") || "value"}: ${issue.message}`).join("; ");
