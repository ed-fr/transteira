// Test data: unique fictitious addresses (example.com / example.org / example.net only) and
// generated file contents with a known SHA-256.
import crypto from 'node:crypto';

/** Lowercase slug usable in an address local part. */
function slug(label: string): string {
  return (
    label
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 30) || 'user'
  );
}

/** Random suffix making an address unique across tests, workers and runs. */
function suffix(): string {
  return crypto.randomBytes(5).toString('hex');
}

/** Unique internal address: `${label}-${random}@example.com` (the tenants' internal domain). */
export function internalEmail(label: string): string {
  return `${slug(label)}-${suffix()}@example.com`;
}

/** Unique external address (outside the internal domain): `${label}-${random}@example.org`. */
export function externalEmail(label: string, domain: 'example.org' | 'example.net' = 'example.org'): string {
  return `${slug(label)}-${suffix()}@${domain}`;
}

/** A generated file, ready for page.setInputFiles or an upload. */
export interface GeneratedFile {
  name: string;
  mimeType: string;
  buffer: Buffer;
  /** Lowercase hexadecimal SHA-256 of buffer. */
  sha256: string;
}

/** Lowercase hexadecimal SHA-256 of data. */
export function sha256(data: Buffer | Uint8Array): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Deterministic pseudo-random content of `size` bytes derived from `seed` (SHA-256 in counter
 * mode): the same seed always gives the same bytes, so expected hashes are reproducible.
 */
export function deterministicBytes(seed: string, size: number): Buffer {
  const out = Buffer.alloc(size);
  let offset = 0;
  for (let counter = 0; offset < size; counter++) {
    const block = crypto.createHash('sha256').update(`${seed}:${counter}`).digest();
    offset += block.copy(out, offset);
  }
  return out;
}

/** A file of `size` bytes with deterministic content (seeded by its name unless seed is given). */
export function makeFile(
  name: string,
  size: number,
  opts: { seed?: string; mimeType?: string } = {},
): GeneratedFile {
  const buffer = deterministicBytes(opts.seed ?? name, size);
  return { name, mimeType: opts.mimeType ?? 'application/octet-stream', buffer, sha256: sha256(buffer) };
}

/** A text file with the given content. */
export function textFile(name: string, content: string): GeneratedFile {
  const buffer = Buffer.from(content, 'utf8');
  return { name, mimeType: 'text/plain', buffer, sha256: sha256(buffer) };
}
