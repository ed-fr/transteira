// Seeded state of the run (test/e2e/.run/state.json, gitignored), written by the global setup
// and read by the tests: identifiers, origins and the credentials of the seeded accounts.
import fs from 'node:fs';
import { AdminApi, type AdminSession } from './api';
import { STATE_FILE, type E2EDatabase } from './env';

/** A seeded tenant. */
export interface SeededTenant {
  id: string;
  name: string;
  fqdn: string;
  /** Browser origin through Caddy (https://<fqdn>[:port]). */
  origin: string;
  /** Sender address of its SMTP configuration. */
  fromAddress: string;
}

/** A seeded admin account. */
export interface SeededAdmin {
  id: string;
  username: string;
  email: string;
  password: string;
  /** API session (cookie + CSRF), separate from the browser session of the storage state. */
  apiSession: AdminSession;
}

/** Content of state.json. */
export interface E2EState {
  db: E2EDatabase;
  /** Direct port of the server on listenHost() (for the API helpers). */
  serverPort: number;
  /** Fake clamd address. */
  clamavAddr: string;
  superAdmin: SeededAdmin & { totpSecret: string };
  /** Delegated admin of entity A only, without TOTP. */
  delegate: SeededAdmin & { tenantIds: string[] };
  tenants: { a: SeededTenant; b: SeededTenant };
  /** API token of entity A (allowed from loopback and the Docker ranges). */
  apiTokenA: string;
}

let cached: E2EState | undefined;

/** Reads state.json (cached per worker). */
export function loadState(): E2EState {
  cached ??= JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')) as E2EState;
  return cached;
}

/** Writes state.json (global setup only). */
export function saveState(state: E2EState): void {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), { mode: 0o600 });
  cached = state;
}

/** Admin API client signed in as the seeded super admin (shared API session). */
export function superAdminApi(): AdminApi {
  const s = loadState();
  return new AdminApi(s.serverPort, { ...s.superAdmin.apiSession });
}

/** Admin API client signed in as the seeded delegated admin of entity A (shared API session). */
export function delegateApi(): AdminApi {
  const s = loadState();
  return new AdminApi(s.serverPort, { ...s.delegate.apiSession });
}
