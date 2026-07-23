import type { CryptoFailure, CryptoFailureReason } from './contract.js';

/**
 * Failures are thrown rather than returned because `OpenResult` in the contract
 * has no error variant. Throwing keeps the happy path free of union narrowing
 * at every call site, and an exception is harder to accidentally ignore than a
 * discriminated union the caller forgot to check.
 *
 * The thrown object structurally satisfies `CryptoFailure`, so callers can
 * catch it and hand it straight to the UI without a translation layer.
 */
export class CryptoFailureError extends Error implements CryptoFailure {
  readonly reason: CryptoFailureReason;

  constructor(reason: CryptoFailureReason, message: string) {
    super(message);
    this.name = 'CryptoFailureError';
    this.reason = reason;
  }
}

export function fail(reason: CryptoFailureReason, message: string): never {
  throw new CryptoFailureError(reason, message);
}

export function isCryptoFailure(value: unknown): value is CryptoFailureError {
  return value instanceof CryptoFailureError;
}
