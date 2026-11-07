// Logic of the Service Worker of the end-to-end encrypted downloads (CLAUDE.md section 22,
// docs/architecture/e2e-format.md), kept apart from the thin entry point sw.ts so that it runs in
// the unit tests (Node, real WebCrypto). See shared/e2e/sw-protocol.ts for the message protocol.
//
// The page registers an entry (a file or an archive) under a random id, then navigates to
// /e2e/<id>. The worker answers that navigation itself: it fetches the ciphertext (same origin,
// with the unlock and recipient verification cookies), decrypts it chunk by chunk, checks the
// plaintext size and SHA-256 declared by the sealed metadata while streaming, and answers an
// attachment. Any failure (authentication, truncation, size or fingerprint mismatch, network)
// errors the response stream before it closes, so the browser marks the download as failed and
// never keeps a truncated or altered file as complete. Nothing is ever held in memory beyond one
// encrypted chunk per file.
//
// A failure before the response starts (expired access, network), and an id that is unknown,
// already used or expired, are answered 204 No Content: a navigation answered 204 leaves the
// download page as it is, and the page learns the reason on its reply port. An entry dropped
// before its request (expired, or evicted beyond MAX_PENDING) reports failed unavailable on its
// port, so that the page never waits for a download that cannot come. Requests outside /e2e/ are
// never answered by the worker.
import { checkPath } from '../shared/validation/filepath';
import { safeFileName } from '../shared/e2e/archive-names';
import { decryptFile, failureCode, openCiphertext } from '../shared/e2e/ciphertext';
import { MAX_INDEX } from '../shared/e2e/tte2';
import { createZipStream, zipSize, type ZipEntry } from '../shared/e2e/zip';
import { safeApiHref } from '../shared/safe/href';
import {
  ENTRY_ID,
  ENTRY_TTL_MS,
  MAX_PENDING,
  SW_SCOPE,
  type SwEntry,
  type SwFile,
  type SwReply,
} from '../shared/e2e/sw-protocol';

/** Path prefix of the ciphertext URLs the worker accepts to fetch. */
export const CIPHERTEXT_PREFIX = '/api/v1/downloads/';

/** Maximum number of files of an archive entry (the server limit of a transfer). */
export const MAX_ARCHIVE_FILES = 1000;

/** Content-Security-Policy of the attachments (the server one, internal/api/public). */
export const ATTACHMENT_CSP = "default-src 'none'; sandbox; frame-ancestors 'none'";

/** The part of a MessagePort the worker uses. */
export type ReplyPort = Pick<MessagePort, 'postMessage'>;

/** Environment of the worker logic (injected by sw.ts, faked by the tests). */
export interface WorkerContext {
  /** Origin of the worker (self.location.origin). */
  readonly origin: string;
  readonly registry: EntryRegistry;
  /** The fetch of the worker. */
  fetch(input: string, init: RequestInit): Promise<Response>;
  /** Current time in milliseconds. */
  now(): number;
  /** Resolves after ms milliseconds (keeps the worker alive while an entry is pending). */
  sleep(ms: number): Promise<void>;
}

/** An entry waiting for its request. */
interface Pending {
  entry: SwEntry;
  port: ReplyPort;
  expires: number;
  release: () => void;
}

/** Reply posted on the port of an entry dropped before its request. */
const DROPPED: SwReply = { type: 'failed', code: 'unavailable' };

/**
 * Entries registered by the pages, by id: single use (take removes them), expired after ttl
 * milliseconds, at most max at once (the oldest is dropped beyond). A dropped entry (expired or
 * evicted) reports failed unavailable on its port.
 */
export class EntryRegistry {
  private readonly entries = new Map<string, Pending>();

  constructor(
    private readonly ttl: number = ENTRY_TTL_MS,
    private readonly max: number = MAX_PENDING,
  ) {}

  /** Number of entries pending (expired ones included until the next sweep). */
  get size(): number {
    return this.entries.size;
  }

  /**
   * Registers entry under id; returns a promise resolved once the entry is taken or dropped, or
   * undefined when the id is already registered.
   */
  add(id: string, entry: SwEntry, port: ReplyPort, now: number): Promise<void> | undefined {
    this.sweep(now);
    if (this.entries.has(id)) return undefined;
    while (this.entries.size >= this.max) {
      const [oldest, p] = this.entries.entries().next().value as [string, Pending];
      this.drop(oldest, p);
    }
    return new Promise<void>((release) => {
      this.entries.set(id, { entry, port, expires: now + this.ttl, release });
    });
  }

  /** Removes and returns the entry of id, undefined when unknown or expired. */
  take(id: string, now: number): { entry: SwEntry; port: ReplyPort } | undefined {
    this.sweep(now);
    const p = this.entries.get(id);
    if (p === undefined) return undefined;
    this.entries.delete(id);
    p.release();
    return { entry: p.entry, port: p.port };
  }

  /**
   * Drops the entry of id if it is still the one registered with entry (its lifetime is over:
   * the worker stops waiting for its request).
   */
  expire(id: string, entry: SwEntry): void {
    const p = this.entries.get(id);
    if (p !== undefined && p.entry === entry) this.drop(id, p);
  }

  private sweep(now: number): void {
    for (const [id, p] of this.entries) {
      if (p.expires <= now) this.drop(id, p);
    }
  }

  private drop(id: string, p: Pending): void {
    this.entries.delete(id);
    p.release();
    p.port.postMessage(DROPPED);
  }
}

const SHA256_HEX = /^[0-9a-f]{64}$/;

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null;
}

/** Validates one file of a registration; member: an archive entry path (checked strictly). */
function parseFile(v: unknown, member: boolean): SwFile | undefined {
  if (!isRecord(v)) return undefined;
  const { url, key, index, name, size, sha256 } = v;
  if (
    typeof url !== 'string' ||
    safeApiHref(url) === undefined ||
    !url.startsWith(CIPHERTEXT_PREFIX) ||
    !(key instanceof CryptoKey) ||
    key.algorithm.name !== 'HKDF' ||
    key.extractable ||
    typeof index !== 'number' ||
    !Number.isSafeInteger(index) ||
    index < 0 ||
    index > MAX_INDEX ||
    typeof name !== 'string' ||
    typeof size !== 'number' ||
    !Number.isSafeInteger(size) ||
    size < 0 ||
    typeof sha256 !== 'string' ||
    !SHA256_HEX.test(sha256)
  ) {
    return undefined;
  }
  if (member) {
    const checked = checkPath(name);
    if (!checked.ok || checked.value !== name) return undefined;
  }
  return { url, key, index, name: member ? name : safeFileName(name), size, sha256 };
}

/**
 * Validates a registration message: its id and its entry (same-origin download URLs only,
 * non-extractable HKDF keys, sizes, fingerprints, archive entry paths valid and unique
 * case-insensitively). Returns undefined for anything else.
 */
export function parseRegistration(data: unknown): { id: string; entry: SwEntry } | undefined {
  if (!isRecord(data) || data['type'] !== 'register') return undefined;
  const { id, entry } = data;
  if (typeof id !== 'string' || !ENTRY_ID.test(id) || !isRecord(entry)) return undefined;
  if (entry['kind'] === 'file') {
    const file = parseFile(entry['file'], false);
    return file === undefined ? undefined : { id, entry: { kind: 'file', file } };
  }
  const list = entry['files'];
  if (
    entry['kind'] !== 'archive' ||
    typeof entry['name'] !== 'string' ||
    !Array.isArray(list) ||
    list.length === 0 ||
    list.length > MAX_ARCHIVE_FILES
  ) {
    return undefined;
  }
  const files: SwFile[] = [];
  const names = new Set<string>();
  for (const item of list) {
    const file = parseFile(item, true);
    const folded = file?.name.toUpperCase().toLowerCase();
    if (file === undefined || names.has(folded!)) return undefined;
    names.add(folded!);
    files.push(file);
  }
  return { id, entry: { kind: 'archive', name: safeFileName(entry['name']), files } };
}

/**
 * Handles a message posted to the worker: a valid registration is recorded and acknowledged on
 * the reply port (ports[0]), anything else is rejected. The returned promise resolves once the
 * entry is taken or expired (the caller passes it to waitUntil so that the worker stays alive).
 */
export async function handleMessage(
  data: unknown,
  ports: readonly ReplyPort[],
  ctx: WorkerContext,
): Promise<void> {
  const port = ports[0];
  if (port === undefined) return;
  const reg = parseRegistration(data);
  const held = reg === undefined ? undefined : ctx.registry.add(reg.id, reg.entry, port, ctx.now());
  if (reg === undefined || held === undefined) {
    port.postMessage({ type: 'rejected' } satisfies SwReply);
    return;
  }
  port.postMessage({ type: 'registered' } satisfies SwReply);
  await Promise.race([held, ctx.sleep(ENTRY_TTL_MS)]);
  // Not taken in time: dropped now (the page is told), not at the next sweep.
  ctx.registry.expire(reg.id, reg.entry);
}

/** Whether b may appear unencoded in an RFC 8187 value (attr-char). */
function isAttrChar(b: number): boolean {
  return (
    (b >= 0x61 && b <= 0x7a) ||
    (b >= 0x41 && b <= 0x5a) ||
    (b >= 0x30 && b <= 0x39) ||
    '!#$&+-.^_`|~'.includes(String.fromCharCode(b))
  );
}

const encoder = new TextEncoder();

/**
 * Content-Disposition of a download named name (RFC 6266), as the server builds it: an ASCII
 * filename fallback (non-ASCII, quotes, backslashes and control characters become "_") and the
 * exact UTF-8 name as filename* (RFC 8187 percent-encoding).
 */
export function contentDisposition(name: string): string {
  const n = name === '' ? 'download' : name;
  let ascii = '';
  for (const ch of n) {
    const c = ch.codePointAt(0)!;
    ascii += c < 0x20 || c > 0x7e || ch === '"' || ch === '\\' ? '_' : ch;
  }
  let ext = '';
  for (const b of encoder.encode(n)) {
    ext += isAttrChar(b) ? String.fromCharCode(b) : `%${b.toString(16).toUpperCase().padStart(2, '0')}`;
  }
  return `attachment; filename="${ascii}"; filename*=UTF-8''${ext}`;
}

/**
 * Headers of a decrypted attachment: always application/octet-stream (never the type declared by
 * the sender: the file is downloaded, never rendered nor sniffed), the exact plaintext length,
 * no storage in any cache and the sandbox CSP of the server attachments.
 */
export function attachmentHeaders(name: string, length: number): Headers {
  return new Headers({
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': contentDisposition(name),
    'Content-Length': String(length),
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': ATTACHMENT_CSP,
  });
}

/**
 * Wraps a response body so that its outcome reaches the page: done once it closes, failed with
 * the code of its error, cancelled when the browser cancels the download.
 */
export function observe(source: ReadableStream<Uint8Array>, port: ReplyPort): ReadableStream<Uint8Array> {
  const reader = source.getReader();
  return new ReadableStream<Uint8Array>(
    {
      async pull(controller) {
        try {
          const { done, value } = await reader.read();
          if (done) {
            controller.close();
            port.postMessage({ type: 'done' } satisfies SwReply);
          } else {
            controller.enqueue(value);
          }
        } catch (err) {
          port.postMessage({ type: 'failed', code: failureCode(err) } satisfies SwReply);
          controller.error(err);
        }
      },
      async cancel(reason) {
        port.postMessage({ type: 'failed', code: 'cancelled' } satisfies SwReply);
        await reader.cancel(reason).catch(() => undefined);
      },
    },
    { highWaterMark: 0 },
  );
}

/** Archive members: the first ciphertext is already open, the next ones are fetched in turn. */
async function* members(
  files: readonly SwFile[],
  first: ReadableStream<Uint8Array>,
  ctx: WorkerContext,
): AsyncGenerator<ZipEntry> {
  const modified = new Date(ctx.now());
  for (const [i, file] of files.entries()) {
    const ciphertext = i === 0 ? first : await openCiphertext(file.url, ctx.fetch);
    yield { name: file.name, size: file.size, modified, data: decryptFile(ciphertext, file) };
  }
}

/** Response of a navigation that must leave the page as it is (failure before streaming). */
function noContent(): Response {
  return new Response(null, {
    status: 204,
    headers: { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
  });
}

/** Answers a registered entry: opens its (first) ciphertext, then streams the attachment. */
async function serve(entry: SwEntry, port: ReplyPort, ctx: WorkerContext): Promise<Response> {
  const files = entry.kind === 'file' ? [entry.file] : entry.files;
  let first: ReadableStream<Uint8Array>;
  try {
    first = await openCiphertext(files[0]!.url, ctx.fetch);
  } catch (err) {
    port.postMessage({ type: 'failed', code: failureCode(err) } satisfies SwReply);
    return noContent();
  }
  let body: ReadableStream<Uint8Array>;
  let headers: Headers;
  if (entry.kind === 'file') {
    body = decryptFile(first, entry.file);
    headers = attachmentHeaders(entry.file.name, entry.file.size);
  } else {
    body = createZipStream(members(entry.files, first, ctx));
    headers = attachmentHeaders(entry.name, zipSize(entry.files));
  }
  port.postMessage({ type: 'started' } satisfies SwReply);
  return new Response(observe(body, port), { status: 200, headers });
}

/**
 * Routes a request of the worker: undefined (not answered, the browser goes to the network) for
 * anything but a GET of the same origin under /e2e/; 204 for an unknown, used or expired id (a
 * navigation then leaves the page as it is, instead of replacing it with an error page); the
 * decrypted attachment otherwise.
 */
export function routeRequest(request: Request, ctx: WorkerContext): Promise<Response> | undefined {
  const url = new URL(request.url);
  if (request.method !== 'GET' || url.origin !== ctx.origin || !url.pathname.startsWith(SW_SCOPE)) {
    return undefined;
  }
  const found = ctx.registry.take(url.pathname.slice(SW_SCOPE.length), ctx.now());
  if (found === undefined) return Promise.resolve(noContent());
  return serve(found.entry, found.port, ctx);
}
