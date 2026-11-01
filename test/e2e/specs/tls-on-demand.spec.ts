// On-demand TLS through the real Caddy (V1.2, OpenAPI askTls, threats T-277 to T-280): the e2e
// Caddyfile has a catch-all site with `tls internal { on_demand }` whose `ask` URL is the
// server's /tls/ask. A tenant created after Caddy started (still in setup) gets a certificate at
// its first TLS handshake; an unknown name gets none; and /tls/ask relayed by Caddy from a public
// site answers 404 although Caddy's address is allowed (relay header present).
import crypto from 'node:crypto';
import https from 'node:https';
import type { TLSSocket } from 'node:tls';
import { HOSTS, HTTPS_PORT } from '../support/env';
import { expect, test } from '../support/fixtures';
import { superAdminApi } from '../support/state';

const GiB = 2 ** 30;

interface Answer {
  status: number;
  body: string;
  /** Subject alternative names of the certificate Caddy presented. */
  altNames: string;
}

/** GET path on Caddy with servername as SNI and Host; rejects when the TLS handshake fails. */
function get(servername: string, path: string): Promise<Answer> {
  return new Promise((resolve, reject) => {
    // Caddy's internal CA is not trusted by Node: the certificate is checked by name below.
    const req = https.get(
      {
        host: '127.0.0.1',
        port: HTTPS_PORT,
        path,
        servername,
        headers: { Host: HTTPS_PORT === 443 ? servername : `${servername}:${HTTPS_PORT}` },
        rejectUnauthorized: false,
        agent: false,
        timeout: 20_000,
      },
      (res) => {
        const altNames = (res.socket as TLSSocket).getPeerCertificate().subjectaltname ?? '';
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (c: string) => (body += c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body, altNames }));
      },
    );
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}

test.describe('on-demand TLS', () => {
  test('certificate for a new tenant only, ask refused when relayed', async () => {
    const id = crypto.randomBytes(4).toString('hex');
    const name = `E2E on-demand ${id}`;
    const fqdn = `od-${id}.localhost`;
    const tenant = await superAdminApi().ok<{ id: string }>(
      'POST',
      '/admin/tenants',
      {
        name,
        fqdn,
        defaultLanguage: 'en',
        storageQuotaBytes: GiB,
        maxTransferBytes: GiB,
        maxTransferCeiling: GiB,
        setupState: 'setup',
      },
      [201],
    );
    try {
      // A tenant in setup: Caddy asks, gets 200, issues a certificate for exactly this name and
      // proxies the request.
      const ok = await get(fqdn, '/healthz');
      expect(ok.status).toBe(200);
      expect(ok.altNames).toContain(`DNS:${fqdn}`);

      // An unknown name: /tls/ask answers 404, Caddy issues nothing and the handshake fails.
      await expect(get(`unknown-${id}.localhost`, '/healthz')).rejects.toThrow();

      // A public request for /tls/ask relayed by Caddy comes from an allowed address but carries
      // X-Forwarded-For: empty 404, whatever the domain asked.
      for (const host of [HOSTS.a, fqdn]) {
        const relayed = await get(host, `/tls/ask?domain=${encodeURIComponent(fqdn)}`);
        expect(relayed.status).toBe(404);
        expect(relayed.body).toBe('');
      }
    } finally {
      await superAdminApi().call('DELETE', `/admin/tenants/${tenant.id}?confirm=${encodeURIComponent(name)}`);
    }
  });
});
