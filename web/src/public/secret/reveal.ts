// Pure logic of the recipient page of a one-time secret /s/:token (V2.1, CLAUDE.md section 22.1;
// format in docs/architecture/e2e-format.md section 3.3). The page reads the key K of the link
// fragment, asks the status (GET, consumes nothing) and, only when the recipient presses the
// button, derives K' (with the passphrase, if any), proves possession of K and K' to the server
// (revealSecret, single use) and opens the sealed text. An optional file is downloaded once with
// the grant of the reveal, decrypted in memory under K' (file index 0), checked against the size
// and SHA-256 of its sealed metadata, and saved under a sanitized name (T-324).
//
// Browser dependencies (API client, fetch) are injected so that the module is tested in Node.
import { ApiProblem, NetworkError, buildUrl, expandPath, type ApiClient } from '../../shared/api/client';
import type { components } from '../../shared/api/schema';
import { safeFileName } from '../../shared/e2e/archive-names';
import { decryptBytes } from '../../shared/e2e/decrypt';
import { isE2EError } from '../../shared/e2e/errors';
import { openMetadata, wellFormed } from '../../shared/e2e/sealed';
import {
  MAX_PASSPHRASE_SIZE,
  PASSPHRASE_ITERATIONS,
  PASSPHRASE_KDF,
  decodePassphraseSalt,
  deriveSecretKey,
  encodeProof,
  openSecret,
  secretKeyProof,
  secretProof,
  type PassphraseDescriptor,
} from '../../shared/e2e/secret';
import { Sha256, toHex } from '../../shared/e2e/sha256';
import { importTransferKey } from '../../shared/e2e/tte2';

/** Status of an active secret (getSecretLink). */
export type SecretStatus = components['schemas']['SecretStatus'];

/** Answer of a successful reveal (revealSecret). */
export type SecretRevealed = components['schemas']['SecretRevealed'];

/** Largest ciphertext of a secret file (the largest fileMaxBytes of a tenant, 25 MiB). */
export const MAX_SECRET_FILE_BYTES = 25 * 1024 * 1024;

/** Header carrying the one-time file grant. */
export const GRANT_HEADER = 'TransTeira-Secret-Grant';

/** Why a secret ended (reason of 410 secret-gone); unknown for a reason added later. */
export type GoneReason = 'read' | 'expired' | 'deleted' | 'locked' | 'unknown';

const GONE_REASONS: readonly GoneReason[] = ['read', 'expired', 'deleted', 'locked'];

/** Failure of the status call or of the reveal. */
export type SecretFailure =
  /** 404: unknown token (or another tenant). */
  | { kind: 'not-found' }
  /** 410 secret-gone. */
  | { kind: 'gone'; reason: GoneReason }
  /** 403 secret-proof-invalid without attemptsRemaining: the key of the link is wrong. */
  | { kind: 'wrong-key' }
  /** 403 secret-proof-invalid with attemptsRemaining: the passphrase is wrong (counted). */
  | { kind: 'wrong-passphrase'; attemptsRemaining: number }
  /** The secret has a passphrase and none was typed (nothing sent). */
  | { kind: 'passphrase-required' }
  /** The passphrase breaks the format rules: too long or not valid Unicode (nothing sent). */
  | { kind: 'passphrase-invalid' }
  /** 429 rate-limited. */
  | { kind: 'rate-limited'; retryAfterSeconds: number | undefined }
  /** 503 maintenance. */
  | { kind: 'maintenance' }
  /** 503 tenant-in-setup. */
  | { kind: 'in-setup' }
  /** No HTTP answer. */
  | { kind: 'network' }
  /** The server sent something the format refuses (descriptor, sealed text). */
  | { kind: 'tampered' }
  /** WebCrypto is missing or failed outside of the format. */
  | { kind: 'unsupported' }
  /** Any other error. */
  | { kind: 'error' };

/** Outcome of the status call. */
export type StatusOutcome =
  { kind: 'active'; status: SecretStatus } | { kind: 'failure'; failure: SecretFailure };

/** The file of a revealed secret, ready to be downloaded once. */
export interface RevealedFile {
  kind: 'ready';
  /** Sanitized name to save the file under. */
  name: string;
  /** Plaintext size declared by the creator (checked after decryption). */
  size: number;
  /** Lowercase hexadecimal SHA-256 of the plaintext declared by the creator (checked). */
  sha256: string;
  /** One-time grant of downloadSecretFile. */
  grant: string;
  /** End of validity of the grant (ISO 8601). */
  grantExpiresAt: string;
}

/** File part of a revealed secret. */
export type RevealedFileState = { kind: 'none' } | RevealedFile | { kind: 'tampered' };

/** A revealed secret. */
export interface RevealedSecret {
  /** Decrypted text, possibly empty for a secret with a file. */
  text: string;
  file: RevealedFileState;
  /** Non-extractable base key of K', for the file. */
  rootKey: CryptoKey;
}

/** Outcome of a reveal. */
export type RevealOutcome =
  { kind: 'revealed'; secret: RevealedSecret } | { kind: 'failure'; failure: SecretFailure };

/** Failure of the file download. */
export type FileFailure =
  /** 404: the grant expired, was already used, or the file is gone. */
  | 'unavailable'
  /** The ciphertext does not decrypt, or its size or fingerprint differs from the metadata. */
  | 'corrupt'
  | 'rate-limited'
  | 'maintenance'
  | 'in-setup'
  | 'network'
  | 'error';

/** Outcome of the file download. */
export type FileOutcome =
  { kind: 'ok'; blob: Blob; name: string } | { kind: 'failure'; failure: FileFailure };

/** Browser dependencies. */
export interface RevealDeps {
  /** API client of the application. */
  api: Pick<ApiClient, 'get' | 'post'>;
  /** fetch, for the binary file download. */
  fetch: typeof fetch;
  /** Base path of the API, default /api/v1. */
  baseUrl?: string;
  /** Whether WebCrypto is available (default: crypto.subtle exists). */
  cryptoAvailable?: () => boolean;
}

function cryptoAvailable(deps: RevealDeps): boolean {
  return deps.cryptoAvailable?.() ?? globalThis.crypto?.subtle !== undefined;
}

/** Classifies an error of the status call or of the reveal. */
export function classifyFailure(err: unknown): SecretFailure {
  if (err instanceof NetworkError) return { kind: 'network' };
  if (!(err instanceof ApiProblem)) return { kind: 'error' };
  switch (err.status) {
    case 404:
      return { kind: 'not-found' };
    case 410: {
      const reason = err.problem?.reason;
      return {
        kind: 'gone',
        reason: GONE_REASONS.includes(reason as GoneReason) ? (reason as GoneReason) : 'unknown',
      };
    }
    case 403:
      if (err.code !== 'secret-proof-invalid') return { kind: 'error' };
      return err.attemptsRemaining === undefined
        ? { kind: 'wrong-key' }
        : { kind: 'wrong-passphrase', attemptsRemaining: err.attemptsRemaining };
    case 429:
      return { kind: 'rate-limited', retryAfterSeconds: err.retryAfterSeconds };
    case 503:
      if (err.code === 'maintenance') return { kind: 'maintenance' };
      if (err.code === 'tenant-in-setup') return { kind: 'in-setup' };
      return { kind: 'error' };
    default:
      return { kind: 'error' };
  }
}

/** Reads the status of a secret (consumes nothing). */
export async function loadStatus(deps: RevealDeps, token: string): Promise<StatusOutcome> {
  try {
    const { data } = await deps.api.get('/secret-links/{secretToken}', { path: { secretToken: token } });
    return { kind: 'active', status: data };
  } catch (err) {
    return { kind: 'failure', failure: classifyFailure(err) };
  }
}

/**
 * Checks a typed passphrase against the rules of the format (non-empty, well-formed, at most
 * MAX_PASSPHRASE_SIZE UTF-8 bytes after NFC); undefined when it is acceptable.
 */
export function passphraseProblem(passphrase: string): SecretFailure | undefined {
  if (passphrase === '') return { kind: 'passphrase-required' };
  if (!wellFormed(passphrase)) return { kind: 'passphrase-invalid' };
  if (new TextEncoder().encode(passphrase.normalize('NFC')).length > MAX_PASSPHRASE_SIZE) {
    return { kind: 'passphrase-invalid' };
  }
  return undefined;
}

/** Whether a descriptor has exactly the parameters of the format (clients refuse any other). */
export function descriptorValid(d: PassphraseDescriptor): boolean {
  if (d.kdf !== PASSPHRASE_KDF || d.iterations !== PASSPHRASE_ITERATIONS) return false;
  try {
    decodePassphraseSalt(d.salt);
    return true;
  } catch {
    return false;
  }
}

/** Maps an error of the local cryptography: a format error is tampered, anything else unsupported. */
function cryptoFailure(err: unknown): SecretFailure {
  return { kind: isE2EError(err) ? 'tampered' : 'unsupported' };
}

/**
 * Reveals the secret (single use): derives K', the key proof and the proof, sends them, then opens
 * the sealed text and, with a file, its sealed metadata. Nothing is sent when the passphrase is
 * missing or invalid, when the status descriptor is not the one of the format, or without
 * WebCrypto. Never rejects.
 */
export async function revealSecret(
  deps: RevealDeps,
  token: string,
  key: Uint8Array,
  passphrase: string,
  status: SecretStatus,
): Promise<RevealOutcome> {
  const fail = (failure: SecretFailure): RevealOutcome => ({ kind: 'failure', failure });
  if (!cryptoAvailable(deps)) return fail({ kind: 'unsupported' });
  const descriptor = status.passphrase ?? null;
  if (descriptor !== null) {
    const problem = passphraseProblem(passphrase);
    if (problem !== undefined) return fail(problem);
    if (!descriptorValid(descriptor)) return fail({ kind: 'tampered' });
  }
  let rootKey: CryptoKey;
  let body: { keyProof: string; proof: string };
  try {
    const rootBytes = await deriveSecretKey(key, descriptor === null ? '' : passphrase, descriptor);
    rootKey = await importTransferKey(rootBytes);
    rootBytes.fill(0);
    body = {
      keyProof: encodeProof(await secretKeyProof(key)),
      proof: encodeProof(await secretProof(rootKey)),
    };
  } catch (err) {
    return fail(cryptoFailure(err));
  }
  let revealed: SecretRevealed;
  try {
    const { data } = await deps.api.post('/secret-links/{secretToken}/reveal', {
      path: { secretToken: token },
      body,
    });
    revealed = data;
  } catch (err) {
    return fail(classifyFailure(err));
  }
  let text: string;
  try {
    text = await openSecret(rootKey, revealed.encryptedText);
  } catch {
    // The secret is consumed by now: whatever the cause, it cannot be shown.
    return fail({ kind: 'tampered' });
  }
  return { kind: 'revealed', secret: { text, rootKey, file: await openFile(rootKey, status, revealed) } };
}

/** Opens the sealed metadata of the file of a revealed secret (index 0, count 1). */
async function openFile(
  rootKey: CryptoKey,
  status: SecretStatus,
  revealed: SecretRevealed,
): Promise<RevealedFileState> {
  const { encryptedMetadata, fileGrant, fileGrantExpiresAt } = revealed;
  if (encryptedMetadata === undefined && fileGrant === undefined && fileGrantExpiresAt === undefined) {
    // A file announced by the status must come with the reveal.
    return status.file === null ? { kind: 'none' } : { kind: 'tampered' };
  }
  if (encryptedMetadata === undefined || fileGrant === undefined || fileGrantExpiresAt === undefined) {
    return { kind: 'tampered' };
  }
  try {
    const m = await openMetadata(rootKey, 0, encryptedMetadata);
    if (m.count !== 1) return { kind: 'tampered' };
    return {
      kind: 'ready',
      name: safeFileName(m.name),
      size: m.size,
      sha256: m.sha256,
      grant: fileGrant,
      grantExpiresAt: fileGrantExpiresAt,
    };
  } catch {
    return { kind: 'tampered' };
  }
}

/** Whether the grant of a file has expired at now (milliseconds since the epoch). */
export function grantExpired(file: Pick<RevealedFile, 'grantExpiresAt'>, now: number): boolean {
  const end = Date.parse(file.grantExpiresAt);
  return Number.isNaN(end) || now >= end;
}

/** Reads the problem code of an error answer of the file download, undefined without one. */
async function problemCode(response: Response): Promise<string | undefined> {
  try {
    const body = (await response.json()) as { code?: unknown } | null;
    return typeof body?.code === 'string' ? body.code : undefined;
  } catch {
    return undefined;
  }
}

/** Maps an error answer of the file download. */
async function fileFailure(response: Response): Promise<FileFailure> {
  switch (response.status) {
    case 404:
      return 'unavailable';
    case 429:
      return 'rate-limited';
    case 503:
      return (await problemCode(response)) === 'maintenance' ? 'maintenance' : 'in-setup';
    default:
      return 'error';
  }
}

/**
 * Reads a response body of at most cap bytes; undefined when it is larger. A declared
 * Content-Length above the cap is refused before anything is read, and the stream is cancelled as
 * soon as it goes beyond the cap: the page never holds more than cap bytes.
 */
export async function readCapped(response: Response, cap: number): Promise<Uint8Array | undefined> {
  const declared = Number(response.headers.get('Content-Length') ?? '');
  const body = response.body;
  if (declared > cap) {
    await body?.cancel();
    return undefined;
  }
  if (body === null) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > cap) {
      await reader.cancel();
      return undefined;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.length;
  }
  return out;
}

/**
 * Downloads the file of a revealed secret once with its grant, decrypts it in memory under K'
 * (file index 0) and checks its size and SHA-256 against the sealed metadata. A ciphertext larger
 * than MAX_SECRET_FILE_BYTES is refused (corrupt) without being read beyond that size. Never
 * rejects.
 */
export async function downloadFile(
  deps: RevealDeps,
  token: string,
  rootKey: CryptoKey,
  file: RevealedFile,
): Promise<FileOutcome> {
  const fail = (failure: FileFailure): FileOutcome => ({ kind: 'failure', failure });
  const url = buildUrl(
    deps.baseUrl ?? '/api/v1',
    expandPath('/secret-links/{secretToken}/file', { secretToken: token }),
  );
  let response: Response;
  let ciphertext: Uint8Array | undefined;
  try {
    response = await deps.fetch(url, {
      method: 'GET',
      headers: { [GRANT_HEADER]: file.grant },
      credentials: 'same-origin',
      cache: 'no-store',
    });
    if (!response.ok) return fail(await fileFailure(response));
    ciphertext = await readCapped(response, MAX_SECRET_FILE_BYTES);
  } catch {
    return fail('network');
  }
  if (ciphertext === undefined) return fail('corrupt');
  let plain: Uint8Array<ArrayBuffer>;
  try {
    plain = await decryptBytes({ key: rootKey, index: 0 }, ciphertext, { expectedPlainSize: file.size });
  } catch (err) {
    return fail(isE2EError(err) ? 'corrupt' : 'error');
  }
  if (toHex(new Sha256().update(plain).digest()) !== file.sha256) return fail('corrupt');
  return { kind: 'ok', blob: new Blob([plain], { type: 'application/octet-stream' }), name: file.name };
}
