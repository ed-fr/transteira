// Fake tus server for the engine tests: keeps the offset and the received bytes of each upload,
// and plays scripted faults (statuses, cuts mid-chunk, stalls, slow progress).
import {
  TransportError,
  type HeadResult,
  type PatchOptions,
  type PatchResult,
  type UploadTransport,
} from './tus';

export type Fault =
  | { kind: 'ok' }
  | { kind: 'status'; status: number; retryAfter?: number; offset?: number }
  | { kind: 'cut'; keep: number }
  | { kind: 'stall'; keep: number }
  | { kind: 'steps'; steps: [delayMs: number, bytes: number][] };

interface ServerUpload {
  offset: number;
  length: number;
  data: Uint8Array;
}

function abortPromise(signal: AbortSignal | undefined): Promise<never> {
  return new Promise((_, reject) => {
    const fail = (): void => reject(new TransportError('aborted', true));
    if (signal?.aborted) fail();
    signal?.addEventListener('abort', fail, { once: true });
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export class FakeServer implements UploadTransport {
  readonly uploads = new Map<string, ServerUpload>();
  readonly headFaults: Fault[] = [];
  readonly patchFaults: Fault[] = [];
  readonly calls: string[] = [];
  terminated: string[] = [];

  add(url: string, length: number, offset = 0): void {
    this.uploads.set(url, { offset, length, data: new Uint8Array(length) });
  }

  bytes(url: string): Uint8Array {
    const u = this.uploads.get(url);
    if (u === undefined) throw new Error(`unknown ${url}`);
    return u.data.slice(0, u.offset);
  }

  private async store(u: ServerUpload, offset: number, body: Blob, count: number): Promise<void> {
    const chunk = new Uint8Array(await body.slice(0, count).arrayBuffer());
    u.data.set(chunk, offset);
    u.offset = offset + chunk.length;
  }

  async head(url: string, signal?: AbortSignal): Promise<HeadResult> {
    this.calls.push(`HEAD ${url}`);
    const fault = this.headFaults.shift();
    await Promise.resolve();
    if (fault?.kind === 'status') {
      const r: HeadResult = { status: fault.status };
      if (fault.retryAfter !== undefined) r.retryAfterSeconds = fault.retryAfter;
      if (fault.offset !== undefined) r.offset = fault.offset;
      return r;
    }
    if (fault?.kind === 'cut') throw new TransportError('network error');
    if (fault?.kind === 'stall') return abortPromise(signal);
    const u = this.uploads.get(url);
    if (u === undefined) return { status: 404 };
    return { status: 200, offset: u.offset, length: u.length };
  }

  async patch(url: string, offset: number, body: Blob, options: PatchOptions = {}): Promise<PatchResult> {
    this.calls.push(`PATCH ${url} ${offset} ${body.size}`);
    const { signal, onProgress } = options;
    if (signal?.aborted) throw new TransportError('aborted', true);
    const u = this.uploads.get(url);
    const fault = this.patchFaults.shift();
    await Promise.resolve();
    if (fault?.kind === 'status') {
      const r: PatchResult = { status: fault.status };
      if (fault.retryAfter !== undefined) r.retryAfterSeconds = fault.retryAfter;
      if (fault.offset !== undefined) r.offset = fault.offset;
      return r;
    }
    if (u === undefined) return { status: 404 };
    if (offset !== u.offset) return { status: 409 };
    if (fault?.kind === 'cut') {
      onProgress?.(fault.keep);
      await this.store(u, offset, body, fault.keep);
      throw new TransportError('network error');
    }
    if (fault?.kind === 'stall') {
      onProgress?.(fault.keep);
      await this.store(u, offset, body, fault.keep);
      return abortPromise(signal);
    }
    if (fault?.kind === 'steps') {
      const aborted = abortPromise(signal);
      aborted.catch(() => {});
      for (const [delay, bytes] of fault.steps) {
        await Promise.race([sleep(delay), aborted]);
        onProgress?.(bytes);
      }
    } else {
      onProgress?.(Math.floor(body.size / 2));
      await Promise.resolve();
      onProgress?.(body.size);
    }
    await this.store(u, offset, body, body.size);
    return { status: 204, offset: u.offset };
  }

  async terminate(url: string): Promise<{ status: number }> {
    this.terminated.push(url);
    return { status: 204 };
  }
}

/** Deterministic content of n bytes. */
export function content(n: number, seed = 1): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 31 + seed) & 0xff;
  return out;
}
