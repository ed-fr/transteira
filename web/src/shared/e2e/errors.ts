// Errors of the TTE2 implementation (docs/architecture/e2e-format.md). Each code mirrors one sentinel
// error of the Go reference (internal/tte2), so that the browser classifies the reference vectors
// exactly like the server and the command-line client.

/**
 * Stable code of an E2EError. Every code but 'size-mismatch' corresponds to a Go sentinel error,
 * named in GO_ERROR_NAMES.
 */
export type E2EErrorCode =
  | 'invalid-key'
  | 'invalid-index'
  | 'invalid-chunk-size'
  | 'bad-header'
  | 'auth'
  | 'truncated'
  | 'trailing-data'
  | 'format'
  | 'counter-overflow'
  | 'encoding'
  | 'invalid-metadata'
  | 'invalid-message'
  | 'invalid-secret'
  | 'invalid-passphrase'
  | 'size-mismatch';

/** Go sentinel error name of each code ('size-mismatch' is a check of the browser only). */
export const GO_ERROR_NAMES: Readonly<Record<E2EErrorCode, string>> = {
  'invalid-key': 'ErrInvalidKey',
  'invalid-index': 'ErrInvalidIndex',
  'invalid-chunk-size': 'ErrInvalidChunkSize',
  'bad-header': 'ErrBadHeader',
  auth: 'ErrAuth',
  truncated: 'ErrTruncated',
  'trailing-data': 'ErrTrailingData',
  format: 'ErrFormat',
  'counter-overflow': 'ErrCounterOverflow',
  encoding: 'ErrEncoding',
  'invalid-metadata': 'ErrInvalidMetadata',
  'invalid-message': 'ErrInvalidMessage',
  'invalid-secret': 'ErrInvalidSecret',
  'invalid-passphrase': 'ErrInvalidPassphrase',
  'size-mismatch': 'ErrSizeMismatch',
};

/** Error raised by the TTE2 functions; code is stable, message is a technical detail (English). */
export class E2EError extends Error {
  /** Stable classification of the failure. */
  readonly code: E2EErrorCode;

  constructor(code: E2EErrorCode, detail?: string) {
    super(detail === undefined ? `tte2: ${code}` : `tte2: ${code}: ${detail}`);
    this.name = 'E2EError';
    this.code = code;
  }
}

/** Reports whether err is an E2EError, optionally with the given code. */
export function isE2EError(err: unknown, code?: E2EErrorCode): err is E2EError {
  return err instanceof E2EError && (code === undefined || err.code === code);
}
