// HTTPS part of the deployment smoke test (scripts/deploy-smoke.sh starts the production stack
// and the reference Caddy, then runs this script). Every request goes through Caddy, exactly as a
// browser or an integration script would: TLS on 127.0.0.1:<SMOKE_HTTPS_PORT> with the SNI and
// Host of the admin or tenant host, the certificate checked against Caddy's internal root CA.
//
// Steps (each one fails the run with a clear message):
//   1. /healthz answers 200 (application, database and the real clamd up), /api/v1/version;
//   2. first-run setup with the setup token printed in the container log, TOTP confirmation;
//   3. a tenant on SMOKE_TENANT_HOST; its public page is served over HTTPS with a strict CSP
//      (TransTeira) and HSTS (Caddy);
//   4. a deposit with an invalid API token is refused and written to the security log with the
//      real client IP, never the proxy address (TT_TRUSTED_PROXIES / X-Forwarded-For work);
//   5. network rules and an API token restricted to that client IP, then a token deposit (tus
//      through Caddy) of a random file and of an EICAR file built at runtime: the real clamd
//      marks the EICAR file infected (audited file.infected), the transfer stays available with
//      the clean file only;
//   6. the recipient view lists the clean file only; the file and the ZIP archive download
//      through Caddy, with the SHA-256 of the original.
//
// Dependency free (Node 24). Configuration through environment variables, see `need` below.
import { execFileSync, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import https from 'node:https';
import path from 'node:path';

const need = (name) => {
  const v = process.env[name];
  if (!v) throw new Error(`deploy-smoke: ${name} is not set`);
  return v;
};

const PORT = Number(need('SMOKE_HTTPS_PORT'));
const CA = fs.readFileSync(need('SMOKE_CA_FILE'));
const ADMIN_HOST = need('SMOKE_ADMIN_HOST');
const TENANT_HOST = need('SMOKE_TENANT_HOST');
const CONTAINER = need('SMOKE_CONTAINER');
const PROXY_IP = need('SMOKE_PROXY_IP');
const WORK_DIR = need('SMOKE_WORK_DIR');
const DOCKER = process.env.DOCKER || 'docker';
/** Domain of the internal sender addresses of the smoke tenant. */
const INTERNAL_DOMAIN = 'example.com';

const log = (msg) => console.log(`deploy-smoke: ${msg}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class SmokeError extends Error {}
function check(cond, msg) {
  if (!cond) throw new SmokeError(msg);
}

/** One HTTPS request through Caddy. body: object (JSON) or Buffer. */
function request(host, method, urlPath, { body, headers = {} } = {}) {
  const h = { Host: host, ...headers };
  let data;
  if (Buffer.isBuffer(body)) data = body;
  else if (body !== undefined) {
    data = Buffer.from(JSON.stringify(body));
    h['Content-Type'] = 'application/json';
  }
  if (data) h['Content-Length'] = data.length;
  return new Promise((resolve, reject) => {
    const req = https.request(
      { host: '127.0.0.1', port: PORT, servername: host, ca: CA, method, path: urlPath, headers: h },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const buf = Buffer.concat(chunks);
          const text = buf.toString('utf8');
          let json;
          try {
            json = JSON.parse(text);
          } catch {
            json = undefined;
          }
          resolve({ status: res.statusCode, headers: res.headers, body: buf, text, json });
        });
      },
    );
    req.on('error', reject);
    req.setTimeout(120_000, () => req.destroy(new Error(`${method} ${urlPath}: timeout`)));
    if (data) req.write(data);
    req.end();
  });
}

function expectStatus(res, want, what) {
  const ok = Array.isArray(want) ? want.includes(res.status) : res.status === want;
  check(ok, `${what}: HTTP ${res.status}, expected ${want}: ${res.text.slice(0, 400)}`);
  return res;
}

// --- Admin client (cookie + CSRF + same-origin headers, as the admin web interface) ---

const admin = { cookie: '', csrf: '' };
async function adminCall(method, p, body, want = [200, 201, 204]) {
  const headers = { Origin: `https://${ADMIN_HOST}`, 'Sec-Fetch-Site': 'same-origin' };
  if (admin.cookie) headers.Cookie = `__Host-tt_admin=${admin.cookie}`;
  if (admin.csrf) headers['X-CSRF-Token'] = admin.csrf;
  const res = await request(ADMIN_HOST, method, `/api/v1${p}`, { body, headers });
  for (const c of res.headers['set-cookie'] ?? []) {
    const m = /^__Host-tt_admin=([^;]*)/.exec(c);
    if (m) admin.cookie = m[1];
  }
  if (typeof res.json?.csrfToken === 'string') admin.csrf = res.json.csrfToken;
  return expectStatus(res, want, `${method} ${p}`).json;
}

// --- TOTP (RFC 6238, same algorithm as test/e2e/support/totp.ts) ---

function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of input.replace(/=+$/, '').toUpperCase()) {
    const idx = alphabet.indexOf(ch);
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

function totp(secret, step = Math.floor(Date.now() / 30_000)) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const h = crypto.createHmac('sha1', base32Decode(secret)).update(msg).digest();
  const off = h[h.length - 1] & 0x0f;
  return String((h.readUInt32BE(off) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

/** The EICAR test signature, assembled at runtime (never stored in the repository). */
function eicar() {
  const backslash = String.fromCharCode(92);
  return Buffer.from(
    ['X5O!P%@AP[4', backslash, 'PZX54(P^)7CC)7}$', 'EICAR-STANDARD-ANTIVIRUS', '-TEST-FILE!$H+H*'].join(''),
    'latin1',
  );
}

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

/** Reads the security log out of the scratch container (no shell in it: docker cp). */
function securityLog() {
  const dst = path.join(WORK_DIR, 'security.log');
  fs.rmSync(dst, { force: true });
  execFileSync(DOCKER, ['cp', `${CONTAINER}:/logs/security.log`, dst], { stdio: ['ignore', 'ignore', 'pipe'] });
  return fs.readFileSync(dst, 'utf8');
}

async function main() {
  // 1. Health and version, on the admin host (no tenant exists yet).
  const health = expectStatus(await request(ADMIN_HOST, 'GET', '/healthz'), 200, 'GET /healthz');
  log(`/healthz 200 through Caddy: ${health.text.trim().slice(0, 200)}`);
  const version = expectStatus(await request(ADMIN_HOST, 'GET', '/api/v1/version'), 200, 'GET /api/v1/version');
  log(`/api/v1/version: ${version.text.trim()}`);

  // 2. First-run setup with the token TransTeira prints while no admin exists.
  // The application may log to stdout or stderr: read both.
  const logs = spawnSync(DOCKER, ['logs', CONTAINER], { encoding: 'utf8' });
  check(logs.status === 0, `docker logs ${CONTAINER} failed: ${logs.stderr}`);
  const m = /Setup token: ([A-Za-z0-9_-]+)/.exec(`${logs.stdout}\n${logs.stderr}`);
  check(m, 'no "Setup token:" line in the transteira container log');
  const enrollment = await adminCall(
    'POST',
    '/admin/setup',
    {
      username: 'smoke-admin',
      email: 'smoke-admin@example.com',
      password: `smoke-${crypto.randomBytes(18).toString('base64url')}`,
      setupToken: m[1],
    },
    [201],
  );
  check(typeof enrollment?.secret === 'string', 'setup did not return a TOTP secret');
  await adminCall('POST', '/admin/me/totp/confirm', { code: totp(enrollment.secret) });
  const me = await adminCall('GET', '/admin/me');
  log(`first-run setup done with the logged setup token, TOTP confirmed (super admin ${me.id})`);

  // 3. Tenant and public page.
  const tenant = await adminCall(
    'POST',
    '/admin/tenants',
    {
      name: 'Smoke Entity',
      fqdn: TENANT_HOST,
      defaultLanguage: 'en',
      storageQuotaBytes: 2 ** 30,
      maxTransferBytes: 2 ** 29,
      maxTransferCeiling: 2 ** 30,
    },
    [201],
  );
  const page = expectStatus(await request(TENANT_HOST, 'GET', '/'), 200, `GET https://${TENANT_HOST}/`);
  const csp = page.headers['content-security-policy'] ?? '';
  check(/default-src/.test(csp) && /frame-ancestors 'none'/.test(csp), `public page CSP missing or weak: "${csp}"`);
  check(/text\/html/.test(page.headers['content-type'] ?? ''), 'public page is not HTML');
  check(/max-age=\d+/.test(page.headers['strict-transport-security'] ?? ''), 'no HSTS header from Caddy');
  check(page.headers['x-content-type-options'] === 'nosniff', 'public page without X-Content-Type-Options: nosniff');
  log(`public page of ${TENANT_HOST} served over HTTPS (CSP, HSTS, nosniff)`);

  // 4. Real client IP through the proxy: an invalid token is logged with it.
  const marker = `smoke-${crypto.randomBytes(4).toString('hex')}`;
  const refused = await request(TENANT_HOST, 'POST', '/api/v1/transfers', {
    body: { senderEmail: `${marker}@${INTERNAL_DOMAIN}`, recipients: ['r@example.org'], expiryDays: 1, files: [] },
    headers: { Authorization: 'Bearer tt_invalid_smoke_token' },
  });
  expectStatus(refused, 401, 'deposit with an invalid API token');
  const line = securityLog()
    .split('\n')
    .filter((l) => l.includes(`tenant=${TENANT_HOST} event=api_token_invalid`))
    .pop();
  check(line, `no api_token_invalid line for ${TENANT_HOST} in the security log`);
  const clientIp = /^\S+ ip=(\S+) /.exec(line)?.[1];
  check(clientIp && clientIp !== '-', `security log line without client IP: ${line}`);
  check(clientIp !== PROXY_IP, `the security log shows the proxy address ${PROXY_IP}, not the client: ${line}`);
  log(`security log: ${line}`);
  log(`real client IP seen through Caddy: ${clientIp} (not the proxy ${PROXY_IP})`);

  // 5. Network rules, API token, token deposit of a clean file and of the EICAR file.
  const cidr = clientIp.includes(':') ? `${clientIp}/128` : `${clientIp}/32`;
  await adminCall('PUT', `/admin/tenants/${tenant.id}/network`, {
    internalCidrs: [cidr],
    internalDomains: [INTERNAL_DOMAIN],
  });
  const token = await adminCall(
    'POST',
    `/admin/tenants/${tenant.id}/api-tokens`,
    { name: 'deploy smoke', allowedCidrs: [cidr] },
    [201],
  );
  const bearer = { Authorization: `Bearer ${token.token}` };

  const clean = crypto.randomBytes(1024 * 1024 + crypto.randomInt(4096));
  const virus = eicar();
  const files = [
    { name: 'smoke-clean.bin', buffer: clean, mediaType: 'application/octet-stream' },
    { name: 'eicar.com', buffer: virus, mediaType: 'application/octet-stream' },
  ];
  const created = expectStatus(
    await request(TENANT_HOST, 'POST', '/api/v1/transfers', {
      body: {
        senderEmail: `smoke-sender@${INTERNAL_DOMAIN}`,
        recipients: ['smoke-recipient@example.org'],
        expiryDays: 1,
        language: 'en',
        files: files.map((f) => ({
          name: f.name,
          size: f.buffer.length,
          mediaType: f.mediaType,
          expectedSha256: sha256(f.buffer),
        })),
      },
      headers: { ...bearer, 'Idempotency-Key': crypto.randomUUID() },
    }),
    201,
    'create transfer with the API token',
  ).json;
  for (const [i, f] of created.files.entries()) {
    expectStatus(
      await request(TENANT_HOST, 'PATCH', f.uploadUrl, {
        body: files[i].buffer,
        headers: {
          ...bearer,
          'Tus-Resumable': '1.0.0',
          'Upload-Offset': '0',
          'Content-Type': 'application/offset+octet-stream',
        },
      }),
      204,
      `tus PATCH ${f.name}`,
    );
  }
  expectStatus(
    await request(TENANT_HOST, 'POST', `/api/v1/transfers/${created.id}/finalize`, { headers: bearer }),
    [200, 202],
    'finalize',
  );
  log(`token deposit ${created.id}: 2 files uploaded with tus through Caddy, finalized`);

  // The real clamd scans both files; poll until the scan is over.
  let transfer;
  const deadline = Date.now() + 5 * 60_000;
  for (;;) {
    transfer = expectStatus(
      await request(TENANT_HOST, 'GET', `/api/v1/transfers/${created.id}`, { headers: bearer }),
      200,
      'GET transfer',
    ).json;
    if (['available', 'rejected', 'expired', 'deleted'].includes(transfer.status)) break;
    check(Date.now() < deadline, `scan still running after 5 minutes (status ${transfer.status})`);
    await sleep(500); // polling interval of the condition above, not a synchronisation sleep
  }
  check(transfer.status === 'available', `transfer status ${transfer.status}, expected available`);
  const byName = Object.fromEntries(transfer.files.map((f) => [f.name, f]));
  check(byName['smoke-clean.bin']?.scanStatus === 'clean', `clean file scan status ${byName['smoke-clean.bin']?.scanStatus}`);
  check(byName['eicar.com']?.scanStatus === 'infected', `EICAR scan status ${byName['eicar.com']?.scanStatus}, expected infected`);
  const audit = await adminCall('GET', `/admin/tenants/${tenant.id}/audit-events`);
  const infected = audit.items.find((e) => e.action === 'file.infected');
  check(infected, 'no file.infected audit event');
  const createdEvt = audit.items.find((e) => e.action === 'transfer.created');
  check(createdEvt?.ip === clientIp, `transfer.created audited with IP ${createdEvt?.ip}, expected ${clientIp}`);
  log(`clamd: clean file "clean", EICAR "infected" (audit file.infected ${JSON.stringify(infected.details ?? {})})`);

  // 6. Recipient view and downloads through Caddy.
  check(transfer.downloadUrl, 'the sender view has no downloadUrl');
  const linkToken = new URL(transfer.downloadUrl).pathname.split('/').pop();
  const view = expectStatus(await request(TENANT_HOST, 'GET', `/api/v1/downloads/${linkToken}`), 200, 'GET download view').json;
  check(view.files.length === 1 && view.files[0].name === 'smoke-clean.bin', `recipient view lists ${view.files.map((f) => f.name)}`);
  check(view.files[0].sha256 === sha256(clean), 'SHA-256 shown to the recipient differs from the original');
  const dl = expectStatus(await request(TENANT_HOST, 'GET', view.files[0].downloadUrl), 200, 'download file');
  check(sha256(dl.body) === sha256(clean), 'downloaded file SHA-256 differs from the original');
  check(/^attachment/.test(dl.headers['content-disposition'] ?? ''), 'download not sent as an attachment');
  check(dl.headers['x-content-type-options'] === 'nosniff', 'download without nosniff');
  check(dl.headers['content-encoding'] === undefined, `download compressed by the proxy (${dl.headers['content-encoding']})`);
  log(`file downloaded through Caddy: ${dl.body.length} bytes, SHA-256 ${sha256(dl.body)} matches the original`);
  const zip = expectStatus(await request(TENANT_HOST, 'GET', view.archiveUrl), 200, 'download archive');
  check(zip.body.subarray(0, 2).toString('latin1') === 'PK', 'archive is not a ZIP');
  check(zip.body.length === Number(zip.headers['content-length']), 'archive length differs from Content-Length');
  check(zip.body.includes(clean.subarray(0, 4096)), 'archive does not contain the clean file (store mode)');
  log(`ZIP archive downloaded through Caddy (${zip.body.length} bytes, store mode)`);

  // 7. Encryption at rest in the production data volume: no stored file holds a plaintext
  // fragment of the deposited files, nor their original names.
  const dataDir = path.join(WORK_DIR, 'data');
  fs.rmSync(dataDir, { recursive: true, force: true });
  execFileSync(DOCKER, ['cp', `${CONTAINER}:/data`, dataDir], { stdio: ['ignore', 'ignore', 'pipe'] });
  const stored = fs.readdirSync(dataDir, { recursive: true, withFileTypes: true }).filter((e) => e.isFile());
  check(stored.length > 0, 'no file in the data volume');
  const probes = [clean.subarray(0, 64), clean.subarray(clean.length - 64), virus.subarray(0, 32)];
  for (const e of stored) {
    const full = path.join(e.parentPath, e.name);
    check(!/smoke-clean|eicar/i.test(full.slice(dataDir.length)), `original file name on disk: ${full}`);
    const content = fs.readFileSync(full);
    for (const p of probes) check(!content.includes(p), `plaintext found in the data volume: ${full}`);
  }
  log(`data volume: ${stored.length} file(s), random names, no plaintext fragment (encrypted at rest)`);
  log('HTTPS checks OK');
}

main().catch((err) => {
  console.error(`deploy-smoke: FAIL: ${err instanceof SmokeError ? err.message : err.stack}`);
  process.exit(1);
});
