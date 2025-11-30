import { z } from "zod";
import { AppError, formatZodIssues } from "./errors";

const HEX_REGEX = /^[0-9a-fA-F]+$/;
const BTC_ADDRESS_REGEX = /^[123mn][a-km-zA-HJ-NP-Z1-9]{24,87}$/;

export const addressSchema = z
  .string({ required_error: "Bitcoin address is required" })
  .trim()
  .min(25)
  .max(90)
  .regex(BTC_ADDRESS_REGEX, "Invalid Bitcoin address format");

export const txIdSchema = z
  .string({ required_error: "Transaction ID is required" })
  .length(64, "txid must be 64 hex characters")
  .regex(HEX_REGEX, "txid must be hex");

export const rawTxSchema = z
  .string({ required_error: "Raw transaction hex is required" })
  .trim()
  .min(2, "Raw transaction cannot be empty")
  .max(12000, "Raw transaction too large")
  .regex(HEX_REGEX, "Raw transaction must be hex")
  .refine((value) => value.length % 2 === 0, "Hex length must be even");

export const networkSchema = z.enum(["mainnet", "testnet"], {
  required_error: "networkType must be provided",
});

export const parseSchema = <T>(schema: z.ZodSchema<T>, value: unknown): T => {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    throw new AppError("Invalid request payload", {
      statusCode: 400,
      code: "VALIDATION_ERROR",
      details: formatZodIssues(parsed.error.issues),
    });
  }
  return parsed.data;
};

export const parseBody = <T>(schema: z.ZodSchema<T>, body: unknown): T => parseSchema(schema, body);
