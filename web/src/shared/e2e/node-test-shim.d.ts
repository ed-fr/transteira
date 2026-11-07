// Minimal typings of the few Node modules the e2e unit tests use as references (the web project
// has no @types/node: the sources run in browsers, only Vitest runs in Node). Test files only.
declare module 'node:crypto' {
  export function randomBytes(size: number): Uint8Array;
  export function createHash(algorithm: 'sha256'): {
    update(data: Uint8Array): { digest(encoding: 'hex'): string };
  };
}
declare module 'node:zlib' {
  const zlib: { crc32(data: Uint8Array): number };
  export default zlib;
}
declare module 'node:child_process' {
  export function spawnSync(command: string, args: string[]): { status: number | null };
  export function execFileSync(command: string, args: string[]): { toString(): string };
}
declare module 'node:fs' {
  export function mkdtempSync(prefix: string): string;
  export function rmSync(path: string, options: { recursive: boolean }): void;
  export function writeFileSync(path: string, data: Uint8Array): void;
}
declare module 'node:os' {
  export function tmpdir(): string;
}
declare module 'node:path' {
  export function join(...parts: string[]): string;
}
