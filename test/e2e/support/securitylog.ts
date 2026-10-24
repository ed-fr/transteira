// Reading the security log of the server under test (docs/operations/security-log.md), written
// in the run directory. Each test has its own client IP (clientip.ts), so filtering on ip= isolates
// the events of one test from those of tests running in parallel.
import fs from 'node:fs';
import path from 'node:path';
import { SERVER_LOG_DIR } from './env';

/** Path of the security log of the run. */
export const SECURITY_LOG = path.join(SERVER_LOG_DIR, 'security.log');

/** Criteria of a security log line. */
export interface SecurityEventMatch {
  /** Client IP (the ip= token). */
  ip: string;
  /** Event type (the event= token). */
  event: string;
  /** Tenant FQDN (the tenant= token), when given. */
  tenant?: string;
  /** Extra quoted fields that must be present, e.g. { reason: 'blocklist' }. */
  fields?: Record<string, string>;
}

function matches(line: string, m: SecurityEventMatch): boolean {
  const tokens = line.split(' ');
  if (tokens[1] !== `ip=${m.ip}`) return false;
  if (m.tenant !== undefined && tokens[2] !== `tenant=${m.tenant}`) return false;
  if (!tokens.includes(`event=${m.event}`)) return false;
  return Object.entries(m.fields ?? {}).every(([k, v]) => line.includes(` ${k}=${JSON.stringify(v)}`));
}

/** Lines of the security log matching m (oldest first). */
export function securityEvents(m: SecurityEventMatch): string[] {
  let text: string;
  try {
    text = fs.readFileSync(SECURITY_LOG, 'utf8');
  } catch {
    return [];
  }
  return text.split('\n').filter((line) => line !== '' && matches(line, m));
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Waits until at least `count` lines match m and returns them. */
export async function waitForSecurityEvents(
  m: SecurityEventMatch,
  opts: { count?: number; timeoutMs?: number } = {},
): Promise<string[]> {
  const count = opts.count ?? 1;
  const deadline = Date.now() + (opts.timeoutMs ?? 10_000);
  for (;;) {
    const found = securityEvents(m);
    if (found.length >= count) return found;
    if (Date.now() > deadline) {
      throw new Error(`security log: ${found.length}/${count} line(s) matching ${JSON.stringify(m)}`);
    }
    await sleep(100);
  }
}
