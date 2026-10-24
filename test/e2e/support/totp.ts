// RFC 6238 TOTP codes for the seeded super admin, without ever reusing a time step.
//
// The server accepts the steps now-1, now and now+1 but refuses any step lower than or equal to
// the last accepted one (internal/crypto/totp.go). freshTotp therefore hands out strictly
// increasing steps, recorded in a file shared by every Playwright worker (with a lock
// directory), and uses the "now+1" step when the current one is taken: one sign-in per step,
// a wait of at most one step only when two codes are needed within the same step.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { RUN_DIR } from './env';

/** TOTP period in seconds. */
export const TOTP_PERIOD = 30;

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Decodes an RFC 4648 base32 string (padding and case are ignored). */
export function base32Decode(input: string): Buffer {
  const clean = input.replace(/=+$/, '').replace(/\s+/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = BASE32.indexOf(ch);
    if (idx < 0) throw new Error('invalid base32 character');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** Time step of the instant ms (milliseconds since the epoch). */
export function totpStep(ms: number = Date.now()): number {
  return Math.floor(ms / 1000 / TOTP_PERIOD);
}

/** The 6-digit code of a base32 secret at a time step (HMAC-SHA1, RFC 6238 defaults). */
export function totpCode(secret: string, step: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const h = crypto.createHmac('sha1', base32Decode(secret)).update(msg).digest();
  const offset = h[h.length - 1]! & 0x0f;
  return String((h.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function lastStepFile(secret: string): string {
  const id = crypto.createHash('sha256').update(secret).digest('hex').slice(0, 16);
  return path.join(RUN_DIR, `totp-${id}.step`);
}

async function withLock<T>(fn: () => Promise<T>): Promise<T> {
  const lock = path.join(RUN_DIR, 'totp.lock');
  fs.mkdirSync(RUN_DIR, { recursive: true });
  const deadline = Date.now() + 120_000;
  for (;;) {
    try {
      fs.mkdirSync(lock);
      break;
    } catch {
      // A lock older than two minutes belongs to a crashed process.
      try {
        if (Date.now() - fs.statSync(lock).mtimeMs > 120_000)
          fs.rmSync(lock, { recursive: true, force: true });
      } catch {
        // removed meanwhile
      }
      if (Date.now() > deadline) throw new Error('TOTP lock not acquired');
      await sleep(50);
    }
  }
  try {
    return await fn();
  } finally {
    fs.rmSync(lock, { recursive: true, force: true });
  }
}

/**
 * Returns a code for a time step never handed out before for this secret, waiting (at most one
 * period) only when the steps now and now+1 are both taken. Safe across workers.
 */
export async function freshTotp(secret: string): Promise<string> {
  return withLock(async () => {
    const file = lastStepFile(secret);
    const last = fs.existsSync(file) ? Number(fs.readFileSync(file, 'utf8')) : -1;
    const target = Math.max(totpStep(), last + 1);
    // The server accepts at most now+1: wait until target is within that window.
    while (target > totpStep() + 1) await sleep(250);
    fs.writeFileSync(file, String(target));
    return totpCode(secret, target);
  });
}
