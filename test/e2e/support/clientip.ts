// Simulated client addresses. The e2e Caddy (caddy.ts) forwards the address announced in the
// test-only X-E2E-Client-IP header as X-Real-IP, so that each browser context has its own client
// IP: per-IP limits of the server do not couple parallel tests, and a test can act as a client
// outside the internal ranges.
import crypto from 'node:crypto';

/** Test-only request header carrying the client IP that Caddy forwards in X-Real-IP. */
export const CLIENT_IP_HEADER = 'X-E2E-Client-IP';

/** A random internal client address (10.0.0.0/8, never .0 or .255 in the last byte). */
export function randomInternalIp(): string {
  const [x, y, z] = crypto.randomBytes(3);
  return `10.${x}.${y}.${1 + (z! % 254)}`;
}

/** An address outside every internal range of the seeded tenants (TEST-NET-3, RFC 5737). */
export function externalIp(): string {
  return `203.0.113.${1 + crypto.randomInt(254)}`;
}
