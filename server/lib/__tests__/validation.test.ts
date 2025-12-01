import { describe, expect, it } from "vitest";
import { addressSchema, rawTxSchema, txIdSchema } from "../validation";

describe("validation schemas", () => {
  it("accepts valid address", () => {
    expect(addressSchema.parse("1BoatSLRHtKNngkdXEeobR76b53LETtpyT")).toBeTruthy();
  });

  it("rejects invalid address", () => {
    expect(() => addressSchema.parse("not-an-address")).toThrow();
  });

  it("enforces txid length and hex", () => {
    expect(() => txIdSchema.parse("abc")).toThrow();
    expect(() => txIdSchema.parse("z".repeat(64))).toThrow();
    expect(txIdSchema.parse("a".repeat(64))).toBeTruthy();
  });

  it("validates raw transaction hex size and even length", () => {
    expect(() => rawTxSchema.parse("ab".repeat(6000))).toThrow();
    expect(() => rawTxSchema.parse("abc"));
    expect(() => rawTxSchema.parse("abc")).toThrow();
    expect(rawTxSchema.parse("ab".repeat(10))).toBeTruthy();
  });
});
