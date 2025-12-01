# Changelog

## Unreleased
- Added centralized error middleware with structured JSON responses and Pino-based logging.
- Introduced strict request validation for Bitcoin inputs (addresses, txids, raw hex) with reusable Zod schemas.
- Updated dependency stack to include Pino logging and Vitest; added test script.
- Created CRYPTO_NOTES, SECURITY guidance, and changelog to document safe usage.
- Added unit tests for validation schemas and Vitest configuration.
