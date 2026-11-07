// Helpers of the download tests: real TTE2 ciphertexts and a fake same-origin server answering
// them like the download API (raw ciphertext, application/octet-stream).
import { prepareFileEncryption, importTransferKey, generateTransferKey } from './tte2';
import { pattern, sha256Hex } from './tte2-helpers.test-helper';
import type { FetchLike } from './ciphertext';

/** An encrypted file and what its sealed metadata would declare. */
export interface EncryptedFile {
  index: number;
  plain: Uint8Array<ArrayBuffer>;
  ciphertext: Uint8Array<ArrayBuffer>;
  sha256: string;
  url: string;
}

/** A transfer key (bytes and base key) with encrypted files. */
export interface Fixture {
  bytes: Uint8Array<ArrayBuffer>;
  key: CryptoKey;
  files: EncryptedFile[];
}

/** Encrypts the given plaintext sizes (64 KiB chunks, so that a few hundred KiB span chunks). */
export async function fixture(sizes: readonly number[]): Promise<Fixture> {
  const bytes = generateTransferKey();
  const key = await importTransferKey(bytes);
  const files: EncryptedFile[] = [];
  for (const [index, size] of sizes.entries()) {
    const plain = pattern(size);
    plain[0] = index; // distinct contents
    const enc = await prepareFileEncryption(key, index, new Blob([plain]), { chunkSize: 64 * 1024 });
    files.push({
      index,
      plain,
      ciphertext: await enc.range(0, enc.size),
      sha256: await sha256Hex(plain),
      url: `/api/v1/downloads/dl_x/files/fil_${index}`,
    });
  }
  return { bytes, key, files };
}

/** Body stream delivering b in pieces of at most piece bytes. */
export function streamOf(b: Uint8Array, piece = 10_000): ReadableStream<Uint8Array> {
  let o = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (o >= b.length) {
        controller.close();
        return;
      }
      controller.enqueue(b.slice(o, o + piece));
      o += piece;
    },
  });
}

/** Fake fetch serving the ciphertexts by URL; overrides answer specific URLs. */
export function fakeServer(
  files: readonly EncryptedFile[],
  overrides: Record<string, () => Promise<Response>> = {},
): FetchLike & { calls: { url: string; init: RequestInit }[] } {
  const calls: { url: string; init: RequestInit }[] = [];
  const fn = async (url: string, init: RequestInit): Promise<Response> => {
    calls.push({ url, init });
    const override = overrides[url];
    if (override !== undefined) return override();
    const f = files.find((x) => x.url === url);
    if (f === undefined) return new Response('nope', { status: 404 });
    return new Response(streamOf(f.ciphertext), {
      status: 200,
      headers: { 'Content-Type': 'application/octet-stream' },
    });
  };
  return Object.assign(fn, { calls });
}

/** Reads a whole stream. */
export async function readAll(stream: ReadableStream<Uint8Array>): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Reads a stream and returns the error it fails with (throws if it closes cleanly). */
export async function readError(stream: ReadableStream<Uint8Array>): Promise<unknown> {
  try {
    await readAll(stream);
  } catch (err) {
    return err;
  }
  throw new Error('stream closed without error');
}

/** Reads the entries of a small store-mode archive (no ZIP64) through its central directory. */
export function readZip(buf: Uint8Array): { name: string; data: Uint8Array }[] {
  const v = new DataView(buf.buffer, buf.byteOffset, buf.length);
  const eocd = buf.length - 22;
  if (v.getUint32(eocd, true) !== 0x06054b50) throw new Error('no end of central directory');
  const count = v.getUint16(eocd + 10, true);
  let p = v.getUint32(eocd + 16, true);
  const out: { name: string; data: Uint8Array }[] = [];
  for (let i = 0; i < count; i++) {
    const size = v.getUint32(p + 24, true);
    const nameLen = v.getUint16(p + 28, true);
    const extraLen = v.getUint16(p + 30, true);
    const local = v.getUint32(p + 42, true);
    const name = new TextDecoder().decode(buf.subarray(p + 46, p + 46 + nameLen));
    const start = local + 30 + v.getUint16(local + 26, true) + v.getUint16(local + 28, true);
    out.push({ name, data: buf.subarray(start, start + size) });
    p += 46 + nameLen + extraLen + v.getUint16(p + 32, true);
  }
  return out;
}
