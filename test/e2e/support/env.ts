// Paths, hosts, ports and run options of the end-to-end suite. Everything is derived from the
// repository layout and from a few E2E_* environment variables (test/README.md).
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Database engine of the run (E2E_DB, sqlite by default). */
export type E2EDatabase = 'sqlite' | 'postgres';

const here = path.dirname(fileURLToPath(import.meta.url));

/** test/e2e directory. */
export const E2E_DIR = path.resolve(here, '..');
/** Repository root. */
export const REPO_ROOT = path.resolve(E2E_DIR, '..', '..');
/** Run directory (gitignored): generated Caddyfile, state.json, storage states, server log. */
export const RUN_DIR = path.join(E2E_DIR, '.run');
/** Seeded identifiers and credentials, written by the global setup. */
export const STATE_FILE = path.join(RUN_DIR, 'state.json');
/** Processes and temporary directory of the current run, for the fallback teardown. */
export const RUNTIME_FILE = path.join(RUN_DIR, 'runtime.json');
/** Directory mounted into the Caddy container (holds the generated Caddyfile). */
export const CADDY_DIR = path.join(RUN_DIR, 'caddy');
/** Browser storage states of the seeded admins. */
export const STORAGE_SUPER = path.join(RUN_DIR, 'storage-super.json');
export const STORAGE_DELEGATE = path.join(RUN_DIR, 'storage-delegate.json');
/** Log directory of the server under test (TT_LOG_DIR: security log), kept after the run. */
export const SERVER_LOG_DIR = path.join(RUN_DIR, 'logs');
/** Application log of the server under test (stdout and stderr). */
export const SERVER_LOG = path.join(RUN_DIR, 'server.log');

/** Compose file of the local test environment (PostgreSQL, Mailpit, Caddy). */
export const COMPOSE_FILE = path.join(REPO_ROOT, 'test', 'docker-compose.test.yml');

/** Server binary produced by `make build` (E2E_SERVER_BINARY overrides it). */
export const SERVER_BINARY = process.env.E2E_SERVER_BINARY ?? path.join(REPO_ROOT, 'bin', 'transteira');

function readDatabase(): E2EDatabase {
  const v = (process.env.E2E_DB ?? 'sqlite').trim();
  if (v !== 'sqlite' && v !== 'postgres') throw new Error(`E2E_DB must be sqlite or postgres, got "${v}"`);
  return v;
}

/** Database engine of the run. */
export const E2E_DB: E2EDatabase = readDatabase();

/** Host names served by Caddy; Chromium resolves *.localhost to the loopback interface. */
export const HOSTS = {
  admin: 'admin.localhost',
  a: 'entity-a.localhost',
  b: 'entity-b.localhost',
} as const;

/** HTTPS port published by Caddy on 127.0.0.1 (E2E_HTTPS_PORT, 443 by default). */
export const HTTPS_PORT = Number(process.env.E2E_HTTPS_PORT ?? '443');

function origin(host: string): string {
  return HTTPS_PORT === 443 ? `https://${host}` : `https://${host}:${HTTPS_PORT}`;
}

/** Browser origins of the three hosts (through Caddy). */
export const ORIGINS = {
  admin: origin(HOSTS.admin),
  a: origin(HOSTS.a),
  b: origin(HOSTS.b),
} as const;

/** The only origins a page may contact (no CDN, no third party). */
export const ALLOWED_ORIGINS: readonly string[] = [ORIGINS.admin, ORIGINS.a, ORIGINS.b];

/** Mailpit (started by `make test-env-up`). */
export const MAILPIT_SMTP_HOST = '127.0.0.1';
export const MAILPIT_SMTP_PORT = Number(process.env.E2E_MAILPIT_SMTP_PORT ?? '51025');
export const MAILPIT_API = process.env.E2E_MAILPIT_API ?? 'http://127.0.0.1:58025';

/** PostgreSQL of the test environment: dedicated database transteira_e2e (test/postgres-init). */
export const PG = {
  database: 'transteira_e2e',
  schema: 'transteira',
  // TEST-ONLY credentials of the throwaway container (test/postgres-init/01-roles.sql).
  appDsn:
    process.env.E2E_POSTGRES_DSN ??
    'postgres://transteira_app:transteira_app@127.0.0.1:55432/transteira_e2e?sslmode=disable&search_path=transteira',
  migrateDsn:
    process.env.E2E_POSTGRES_MIGRATE_DSN ??
    'postgres://transteira_owner:transteira_owner@127.0.0.1:55432/transteira_e2e?sslmode=disable&search_path=transteira',
  /** Superuser of the container, used through `docker compose exec` to reset the database. */
  superuser: 'transteira_test',
} as const;

/** Name of the Docker network Caddy is attached to (the default network of the compose project). */
export const COMPOSE_NETWORK = process.env.E2E_COMPOSE_NETWORK ?? 'transteira-test_default';

const isLinux = process.platform === 'linux';

/**
 * IPv4 address of the running Caddy container on COMPOSE_NETWORK (launchCaddy in caddy.ts
 * must have started it).
 */
function caddyAddress(): string {
  let out: string;
  try {
    const id = execFileSync(
      'docker',
      ['compose', '-f', COMPOSE_FILE, '--profile', 'e2e', 'ps', '-q', 'caddy'],
      {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    ).trim();
    if (!id) throw new Error('no running Caddy container');
    out = execFileSync(
      'docker',
      [
        'inspect',
        id,
        '--format',
        `{{with index .NetworkSettings.Networks "${COMPOSE_NETWORK}"}}{{.IPAddress}}{{end}}`,
      ],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    ).trim();
  } catch (e) {
    throw new Error(`cannot read the address of the Caddy container: ${(e as Error).message}`);
  }
  if (!out) throw new Error(`the Caddy container has no IPv4 address on the network "${COMPOSE_NETWORK}"`);
  return out;
}

/** IPv4 gateway of the default Docker bridge (`docker network inspect bridge`). */
function bridgeGateway(): string {
  let out: string;
  try {
    out = execFileSync(
      'docker',
      ['network', 'inspect', 'bridge', '--format', '{{range .IPAM.Config}}{{.Gateway}} {{end}}'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    );
  } catch (e) {
    throw new Error(`cannot inspect the default Docker bridge (is Docker running?): ${(e as Error).message}`);
  }
  // IPv4 first: the server listens on, and trusts, IPv4 addresses.
  const v4 = out
    .split(/\s+/)
    .filter(Boolean)
    .find((v) => !v.includes(':'));
  if (!v4) throw new Error(`the default Docker bridge has no IPv4 gateway (got "${out.trim()}")`);
  return v4;
}

/**
 * Memoizes a value in an environment variable, so that the Playwright workers (which inherit
 * the environment of the main process) do not run docker again.
 */
function memoized(name: string, compute: () => string): string {
  const cached = process.env[name];
  if (cached) return cached;
  const value = compute();
  process.env[name] = value;
  return value;
}

/**
 * Address the server listens on, and the address the API helpers call it on directly. Caddy
 * reaches the server through host.docker.internal: on Docker Desktop (Windows, macOS) that
 * arrives on the loopback interface, so the server listens on 127.0.0.1; on Linux
 * host.docker.internal is the gateway of the default Docker bridge (host-gateway, usually
 * 172.17.0.1), so the server listens on that address only, never on every interface.
 * E2E_LISTEN_HOST overrides it.
 */
export function listenHost(): string {
  return memoized('E2E_LISTEN_HOST', () => (isLinux ? bridgeGateway() : '127.0.0.1'));
}

/**
 * Trusted proxies (TT_TRUSTED_PROXIES): the addresses whose X-Forwarded-For / X-Real-IP the
 * server believes. Loopback on Docker Desktop, where both Caddy's connections and the API
 * helpers arrive. On Linux, Caddy's connections come from its address on the compose network
 * (no NAT for traffic to a host address), so that address is trusted (a /32: the network's
 * gateway, the source of the browser's connections that Docker forwards to Caddy's published
 * port, must stay untrusted, or the client address Caddy forwards for them would be dropped),
 * plus the source of the API helpers' direct calls: the listening address itself, and the
 * address Docker Engine's masquerade rule rewrites it to when there is one (see
 * helperSourceAddress); never a whole network. Caddy must be running (launchCaddy) when it is
 * first computed. E2E_TRUSTED_PROXIES overrides it.
 */
export function trustedProxies(): string {
  return memoized('E2E_TRUSTED_PROXIES', () => {
    if (!isLinux) return '127.0.0.1,::1';
    const listen = listenHost();
    const seen = helperSourceAddress(listen);
    const helpers = seen === listen ? [`${listen}/32`] : [`${listen}/32`, `${seen}/32`];
    return [...helpers, `${caddyAddress()}/32`].join(',');
  });
}

/**
 * Source address the server sees for a connection made from this host to host:port, measured
 * with a throwaway listener on host (in a child process, the callers being synchronous).
 * Docker Engine on Linux masquerades every packet whose source is in the default bridge subnet
 * and which does not leave through docker0 (rule `ip saddr 172.17.0.0/16 oifname != docker0
 * masquerade`): a call from the host to the bridge gateway goes through lo, and arrives with
 * the address of the host's outgoing interface instead of the gateway's. Docker Desktop has no
 * such rule. The address is measured, never assumed, so that nothing depends on the host.
 */
function helperSourceAddress(host: string): string {
  // With `node -e`, process.argv[1] is the first argument after the script: the host.
  const script = `
    const net = require('node:net');
    const srv = net.createServer((sock) => {
      process.stdout.write(sock.remoteAddress.replace(/^::ffff:/, ''));
      sock.destroy();
      srv.close();
    });
    srv.listen(0, process.argv[1], () => net.connect(srv.address().port, process.argv[1]).on('error', () => {}));
    setTimeout(() => process.exit(1), 5000).unref();
  `;
  let out: string;
  try {
    out = execFileSync(process.execPath, ['-e', script, host], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 10_000,
    }).trim();
  } catch (e) {
    throw new Error(`cannot measure the source address of a connection to ${host}: ${(e as Error).message}`);
  }
  if (!out) throw new Error(`no source address measured for a connection to ${host}`);
  return out;
}

/**
 * Internal networks of the seeded tenants: loopback (direct API calls of the helpers) and the
 * private ranges the browser's address takes once it went through Docker's port publishing.
 */
export const TENANT_CIDRS = ['127.0.0.1/32', '::1/128', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'];

/** Internal mail domain of the seeded tenants (only example.com addresses are used). */
export const INTERNAL_DOMAIN = 'example.com';

/** Largest file the server sends to clamd (TT_CLAMAV_MAX_SCAN_BYTES): bigger ones are "not scanned". */
export const CLAMAV_MAX_SCAN_BYTES = 1024 * 1024;

/**
 * Options of fs.rmSync for the run's directory trees: on Windows, files of a server that just
 * stopped (database, logs) may stay locked for a moment, so the removal is retried.
 */
export const RM_TREE = { recursive: true, force: true, maxRetries: 5, retryDelay: 200 } as const;

/** Temporary root of one run (data, database, backups, logs, secrets). */
export function newTempRoot(): string {
  return path.join(os.tmpdir(), `transteira-e2e-${E2E_DB}-${process.pid}-${Date.now()}`);
}
