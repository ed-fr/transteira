// Starts and stops the server under test: the `bin/transteira serve` binary built by
// `make build`, on a free port of listenHost() (loopback, or the Docker bridge gateway on
// Linux), with every directory in a throwaway temporary root and a fresh random master key and
// setup token.
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import {
  CLAMAV_MAX_SCAN_BYTES,
  E2E_DB,
  HOSTS,
  MAILPIT_SMTP_HOST,
  MAILPIT_SMTP_PORT,
  PG,
  SERVER_BINARY,
  SERVER_LOG,
  SERVER_LOG_DIR,
  listenHost,
  trustedProxies,
} from './env';

/** Options of startServer. */
export interface ServerOptions {
  /** Temporary root of the run; every directory and secret of the server lives below it. */
  root: string;
  /** clamd address (the fake clamd). */
  clamavAddr: string;
  /** Extra TT_* variables (they override the defaults). */
  env?: Record<string, string>;
}

/** A running server. */
export interface RunningServer {
  /** Direct (non-proxied) port on listenHost(), used by the API helpers. */
  readonly port: number;
  readonly pid: number;
  /** First-run setup token (TT_SETUP_TOKEN_FILE). */
  readonly setupToken: string;
  stop(): Promise<void>;
}

/** Returns a TCP port that was free a moment ago on the given host. */
export async function freePort(host = '127.0.0.1'): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, host, () => {
      const { port } = srv.address() as net.AddressInfo;
      srv.close(() => resolve(port));
    });
  });
}

function writeSecret(file: string, value: string): void {
  fs.writeFileSync(file, value, { encoding: 'ascii', mode: 0o600 });
}

/** Polls GET /healthz (Host: admin host) until it answers 200, or throws after timeoutMs. */
export async function waitHealthy(port: number, child: ChildProcess, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let last = 'no answer';
  while (Date.now() < deadline) {
    if (child.exitCode !== null)
      throw new Error(`server exited with code ${child.exitCode}; see ${SERVER_LOG}`);
    try {
      const res = await fetch(`http://${listenHost()}:${port}/healthz`, {
        headers: { Host: HOSTS.admin },
        signal: AbortSignal.timeout(2_000),
      });
      last = `${res.status} ${await res.text()}`;
      if (res.status === 200) return;
    } catch (e) {
      last = (e as Error).message;
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`server not healthy after ${timeoutMs} ms (last: ${last}); see ${SERVER_LOG}`);
}

/** Stops a process: graceful signal first (POSIX), forced kill after graceMs. */
export async function stopProcess(child: ChildProcess, graceMs = 10_000): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise<void>((resolve) => child.once('exit', () => resolve()));
  // On Windows there is no SIGTERM: kill() terminates the process at once.
  child.kill('SIGTERM');
  const timer = setTimeout(() => child.kill('SIGKILL'), graceMs);
  await exited;
  clearTimeout(timer);
}

/** True when pid is a running transteira server (guards against a reused PID). */
function isTransteira(pid: number): boolean {
  try {
    const out =
      process.platform === 'win32'
        ? execFileSync('tasklist', ['/FI', `PID eq ${pid}`, '/FO', 'CSV', '/NH'], { encoding: 'utf8' })
        : execFileSync('ps', ['-p', String(pid), '-o', 'comm='], { encoding: 'utf8' });
    return /transteira/i.test(out);
  } catch {
    return false;
  }
}

/** Kills a server left by an earlier, interrupted run (by PID, only if it is still a transteira process). */
export function killStale(pid: number | undefined): void {
  if (!pid || !isTransteira(pid)) return;
  try {
    process.kill(pid, 'SIGKILL');
  } catch {
    // already gone
  }
}

/** Starts the server and waits until /healthz answers 200. */
export async function startServer(opts: ServerOptions): Promise<RunningServer> {
  if (!fs.existsSync(SERVER_BINARY)) throw new Error(`${SERVER_BINARY} is missing: run "make build" first`);
  const dirs = {
    data: path.join(opts.root, 'data'),
    db: path.join(opts.root, 'db'),
    backups: path.join(opts.root, 'backups'),
    // In the run directory, so that the security log survives the run for diagnostics.
    logs: SERVER_LOG_DIR,
    secrets: path.join(opts.root, 'secrets'),
  };
  for (const d of Object.values(dirs)) fs.mkdirSync(d, { recursive: true });

  const masterKeyFile = path.join(dirs.secrets, 'master_key');
  writeSecret(masterKeyFile, crypto.randomBytes(32).toString('base64'));
  const setupToken = `e2e-setup-${crypto.randomBytes(18).toString('base64url')}`;
  const setupTokenFile = path.join(dirs.secrets, 'setup_token');
  writeSecret(setupTokenFile, setupToken);

  const host = listenHost();
  const port = await freePort(host);
  const database: Record<string, string> =
    E2E_DB === 'postgres'
      ? { TT_DB_DRIVER: 'postgres', TT_DB_DSN: PG.appDsn, TT_DB_MIGRATE_DSN: PG.migrateDsn }
      : { TT_DB_DRIVER: 'sqlite', TT_DB_DSN: path.join(dirs.db, 'transteira.db') };

  // Only TT_* variables from this list reach the server: a TT_* variable of the developer's
  // shell must not change the run.
  const inherited = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('TT_')));
  const env: Record<string, string | undefined> = {
    ...inherited,
    ...database,
    TT_DATA_DIR: dirs.data,
    TT_BACKUP_DIR: dirs.backups,
    TT_LOG_DIR: dirs.logs,
    TT_MASTER_KEY_FILE: masterKeyFile,
    TT_SETUP_TOKEN_FILE: setupTokenFile,
    TT_ADMIN_HOSTS: HOSTS.admin,
    TT_LISTEN_ADDR: `${host}:${port}`,
    TT_TRUSTED_PROXIES: trustedProxies(),
    TT_CLAMAV_ADDR: opts.clamavAddr,
    TT_CLAMAV_MAX_SCAN_BYTES: String(CLAMAV_MAX_SCAN_BYTES),
    // Tenant SMTP servers point at Mailpit on loopback, denied by default (SSRF protection).
    TT_SMTP_DENY_NETWORKS: '169.254.0.0/16',
    // Webhook receivers of the e2e specs listen on 127.0.0.1 over plain HTTP.
    TT_WEBHOOK_ALLOW_NETWORKS: '127.0.0.0/8',
    TT_WEBHOOK_ALLOW_HTTP_NETWORKS: '127.0.0.0/8',
    TT_SYSTEM_SMTP_HOST: MAILPIT_SMTP_HOST,
    TT_SYSTEM_SMTP_PORT: String(MAILPIT_SMTP_PORT),
    TT_SYSTEM_SMTP_SECURITY: 'none',
    TT_SYSTEM_SMTP_FROM: 'transteira@example.com',
    TT_LOG_LEVEL: 'debug',
    ...opts.env,
  };

  // `make build` writes bin/transteira without extension, which Windows cannot execute: run a
  // copy named .exe from the temporary root there.
  let binary = SERVER_BINARY;
  if (process.platform === 'win32' && !binary.toLowerCase().endsWith('.exe')) {
    binary = path.join(opts.root, 'transteira.exe');
    fs.copyFileSync(SERVER_BINARY, binary);
  }

  fs.mkdirSync(path.dirname(SERVER_LOG), { recursive: true });
  const log = fs.openSync(SERVER_LOG, 'a');
  fs.writeSync(log, `\n=== ${new Date().toISOString()} start (${E2E_DB}) port ${port}\n`);
  const child = spawn(binary, ['serve'], { env, stdio: ['ignore', log, log], windowsHide: true });
  fs.closeSync(log);
  if (child.pid === undefined) throw new Error(`cannot start ${binary}`);

  try {
    await waitHealthy(port, child);
  } catch (e) {
    await stopProcess(child, 2_000);
    throw e;
  }
  return { port, pid: child.pid, setupToken, stop: () => stopProcess(child) };
}
