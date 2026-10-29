// Deposits made through the public API from Node (no browser), to create the transfers and
// invitations a scenario needs before it drives a screen:
//   - tokenDeposit: an automated deposit with an API token (create, one tus PATCH per file,
//     finalize, then wait for the end of the antivirus scan). No email verification;
//   - openDepositSession: identification of a depositor by email code (Mailpit), giving the
//     deposit session cookie and CSRF token of the session;
//   - sessionDeposit and createInvitation: a deposit or an invitation within that session;
//   - createTenantToken and recipientPath: an extra API token of a tenant, and the path of the
//     personal download link of a recipient, read in the mail they received (no API answer
//     carries a download link) to open on a tenant origin through Caddy.
// Requests go straight to the server (support/api.ts) with the Host header of the tenant and a
// client IP announced in X-Real-IP (loopback is a trusted proxy in the e2e configuration). Each
// session uses a fresh random internal IP by default, so the per-IP limit of verification codes
// (20 per hour) does not couple tests. No Origin header is sent: requests without Origin or
// Sec-Fetch-Site are checked on the CSRF token alone (scripts).
import crypto from 'node:crypto';
import { request, type ApiResponse } from './api';
import { randomInternalIp } from './clientip';
import { HOSTS } from './env';
import type { GeneratedFile } from './data';
import { linksOf, waitForCode, waitForMails } from './mailpit';
import { loadState, superAdminApi } from './state';

/** Terminal states of a finalized transfer (the scan is over). */
const SETTLED = new Set(['available', 'rejected', 'expired', 'deleted']);

/** Options common to the deposits. */
export interface DepositOptions {
  /** Host of the tenant (default entity-a.localhost). */
  host?: string;
  /** Client IP announced to the server (default: loopback for tokens, random internal for sessions). */
  clientIp?: string;
}

/** Content of a transfer to create. */
export interface TransferSpec {
  recipients: string[];
  files: GeneratedFile[];
  expiryDays?: 1 | 7 | 30;
  message?: string;
  password?: string;
  deleteAfterFirstDownload?: boolean;
  /** Maximum number of downloads (V1.1). */
  maxDownloads?: number;
  /** Key of the confidentiality level (V1.1; the tenant default when omitted). */
  confidentialityLevel?: string;
  /** Every recipient proves their address by code before downloading (V1.1). */
  recipientVerification?: boolean;
  /** Language of the recipients' mails and of the download page default (default "en"). */
  language?: 'en' | 'fr';
}

/** Outcome of a deposit that went through. */
export interface DepositResult {
  /** Transfer identifier (trf_...). */
  id: string;
  /** Final status once the scan is over (normally "available"). */
  status: string;
  /** Instant (ms since the epoch) before the deposit started: recipient mails are searched after it. */
  startedAt: number;
  /** Last GET /transfers/{id} body. */
  transfer: SenderTransfer;
}

/** Fields of SenderTransfer used by the helpers. */
export interface SenderTransfer {
  id: string;
  status: string;
  senderEmail: string;
  recipients: string[];
  files: {
    id: string;
    name: string;
    size: number;
    uploadUrl?: string;
    scanStatus?: string;
    sha256?: string;
  }[];
}

/** Error raised when a step of a deposit gets an unexpected answer (the answer is attached). */
export class DepositError extends Error {
  constructor(
    readonly step: string,
    readonly response: ApiResponse,
  ) {
    super(`${step} -> ${response.status} ${response.text.slice(0, 500)}`);
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Sends one request authenticated by `auth` (bearer token, or session cookie and CSRF token). */
function call<T>(
  auth: Auth,
  method: string,
  path: string,
  opts: { body?: unknown; headers?: Record<string, string> } = {},
): Promise<ApiResponse<T>> {
  const headers: Record<string, string> = { ...opts.headers };
  if (auth.kind === 'token') {
    headers.Authorization = `Bearer ${auth.token}`;
  } else {
    headers.Cookie = `__Host-tt_deposit=${auth.session.cookie}`;
    headers['X-CSRF-Token'] = auth.session.csrf;
  }
  return request<T>(loadState().serverPort, method, path, {
    host: auth.host,
    clientIp: auth.clientIp,
    body: opts.body,
    headers,
  });
}

type Auth =
  | { kind: 'token'; token: string; host: string; clientIp: string }
  | { kind: 'session'; session: DepositSession; host: string; clientIp: string };

/** Uploads every file (one PATCH each), finalizes, then waits until the scan is over. */
async function uploadAndFinalize(
  auth: Auth,
  created: SenderTransfer,
  files: GeneratedFile[],
  startedAt: number,
): Promise<DepositResult> {
  for (const [i, file] of created.files.entries()) {
    const content = files[i]!.buffer;
    const res = await call(auth, 'PATCH', file.uploadUrl!, {
      body: content,
      headers: {
        'Tus-Resumable': '1.0.0',
        'Upload-Offset': '0',
        'Content-Type': 'application/offset+octet-stream',
      },
    });
    if (res.status !== 204) throw new DepositError(`PATCH ${file.name}`, res);
  }
  const fin = await call<SenderTransfer>(auth, 'POST', `/api/v1/transfers/${created.id}/finalize`);
  if (fin.status < 200 || fin.status >= 300) throw new DepositError('finalize', fin);
  const deadline = Date.now() + 30_000;
  for (;;) {
    const res = await call<SenderTransfer>(auth, 'GET', `/api/v1/transfers/${created.id}`);
    if (res.status !== 200) throw new DepositError('GET transfer', res);
    if (SETTLED.has(res.json.status))
      return {
        id: created.id,
        status: res.json.status,
        startedAt,
        transfer: res.json,
      };
    if (Date.now() > deadline) throw new DepositError('scan still running after 30 s', res);
    // Polling interval of the condition above (not a synchronisation sleep).
    await sleep(200);
  }
}

function transferBody(spec: TransferSpec, senderEmail?: string): Record<string, unknown> {
  return {
    ...(senderEmail === undefined ? {} : { senderEmail }),
    recipients: spec.recipients,
    expiryDays: spec.expiryDays ?? 7,
    ...(spec.message === undefined ? {} : { message: spec.message }),
    ...(spec.password === undefined ? {} : { password: spec.password }),
    ...(spec.deleteAfterFirstDownload === undefined
      ? {}
      : { deleteAfterFirstDownload: spec.deleteAfterFirstDownload }),
    ...(spec.maxDownloads === undefined ? {} : { maxDownloads: spec.maxDownloads }),
    ...(spec.confidentialityLevel === undefined ? {} : { confidentialityLevel: spec.confidentialityLevel }),
    ...(spec.recipientVerification === undefined
      ? {}
      : { recipientVerification: spec.recipientVerification }),
    language: spec.language ?? 'en',
    files: spec.files.map((f) => ({
      name: f.name,
      size: f.buffer.length,
      mediaType: f.mimeType,
      expectedSha256: f.sha256,
    })),
  };
}

/**
 * Starts a transfer with an API token (POST /transfers) and returns the raw answer, without
 * uploading anything: for tests that only check whether the token is accepted (401 once revoked).
 */
export function tokenCreateTransfer(
  token: string,
  senderEmail: string,
  spec: TransferSpec,
  opts: DepositOptions = {},
): Promise<ApiResponse<SenderTransfer>> {
  const auth: Auth = {
    kind: 'token',
    token,
    host: opts.host ?? HOSTS.a,
    clientIp: opts.clientIp ?? '127.0.0.1',
  };
  return call<SenderTransfer>(auth, 'POST', '/api/v1/transfers', {
    body: transferBody(spec, senderEmail),
    headers: { 'Idempotency-Key': crypto.randomUUID() },
  });
}

/**
 * Complete deposit with an API token: create, upload, finalize, wait for the scan. The token must
 * allow the client IP (default 127.0.0.1) and the sender address (an internal address).
 * Throws a DepositError on any unexpected answer.
 */
export async function tokenDeposit(
  token: string,
  senderEmail: string,
  spec: TransferSpec,
  opts: DepositOptions = {},
): Promise<DepositResult> {
  const auth: Auth = {
    kind: 'token',
    token,
    host: opts.host ?? HOSTS.a,
    clientIp: opts.clientIp ?? '127.0.0.1',
  };
  const startedAt = Date.now() - 2000;
  const created = await tokenCreateTransfer(token, senderEmail, spec, opts);
  if (created.status !== 201) throw new DepositError('create transfer', created);
  return uploadAndFinalize(auth, created.json, spec.files, startedAt);
}

/** A deposit session (cookie value and CSRF token) and where it was opened. */
export interface DepositSession {
  email: string;
  cookie: string;
  csrf: string;
  host: string;
  clientIp: string;
}

function cookieOf(res: ApiResponse, name: string): string | undefined {
  for (const c of res.headers['set-cookie'] ?? []) {
    const m = new RegExp(`^${name}=([^;]*)`).exec(c);
    if (m) return m[1];
  }
  return undefined;
}

/**
 * Identifies `email` on the tenant (internal address from an internal IP, or an external one with
 * invitationToken): requests a code, reads it in Mailpit and confirms it.
 */
export async function openDepositSession(
  email: string,
  opts: DepositOptions & { invitationToken?: string } = {},
): Promise<DepositSession> {
  const host = opts.host ?? HOSTS.a;
  const clientIp = opts.clientIp ?? randomInternalIp();
  const port = loadState().serverPort;
  const after = Date.now() - 2000;
  const start = await request<{ challengeId?: string; csrfToken?: string }>(
    port,
    'POST',
    '/api/v1/deposit-sessions',
    {
      host,
      clientIp,
      body: { email, ...(opts.invitationToken ? { invitationToken: opts.invitationToken } : {}) },
    },
  );
  let res: ApiResponse<{ csrfToken?: string }> = start;
  if (start.status === 202) {
    const code = await waitForCode(email, after);
    res = await request(port, 'POST', `/api/v1/verification-challenges/${start.json.challengeId}/confirm`, {
      host,
      clientIp,
      body: { code },
    });
  }
  const cookie = cookieOf(res, '__Host-tt_deposit');
  if (res.status !== 201 || !cookie || !res.json.csrfToken) throw new DepositError('deposit session', res);
  return { email, cookie, csrf: res.json.csrfToken, host, clientIp };
}

function sessionAuth(session: DepositSession): Auth {
  return { kind: 'session', session, host: session.host, clientIp: session.clientIp };
}

/** Complete deposit within a deposit session (the sender is the session address). */
export async function sessionDeposit(session: DepositSession, spec: TransferSpec): Promise<DepositResult> {
  const auth = sessionAuth(session);
  const startedAt = Date.now() - 2000;
  const created = await call<SenderTransfer>(auth, 'POST', '/api/v1/transfers', {
    body: transferBody(spec),
    headers: { 'Idempotency-Key': crypto.randomUUID() },
  });
  if (created.status !== 201) throw new DepositError('create transfer', created);
  return uploadAndFinalize(auth, created.json, spec.files, startedAt);
}

/** An invitation as returned by POST /invitations. */
export interface CreatedInvitation {
  id: string;
  email: string;
  invitedBy: string;
  status: string;
}

/** Invites `email` from an internal deposit session (an invitation mail goes to Mailpit). */
export async function createInvitation(
  session: DepositSession,
  email: string,
  message?: string,
): Promise<CreatedInvitation> {
  const res = await call<CreatedInvitation>(sessionAuth(session), 'POST', '/api/v1/invitations', {
    body: { email, language: 'en', ...(message === undefined ? {} : { message }) },
  });
  if (res.status !== 201) throw new DepositError('create invitation', res);
  return res.json;
}

/**
 * Creates an extra API token for a tenant as the super admin, allowed from loopback and from the
 * Docker bridge networks (the client IPs the helpers announce).
 */
export async function createTenantToken(
  tenantId: string,
  name: string,
): Promise<{ id: string; token: string }> {
  return superAdminApi().ok<{ id: string; token: string }>(
    'POST',
    `/admin/tenants/${tenantId}/api-tokens`,
    { name, allowedCidrs: ['127.0.0.1/32', '172.16.0.0/12'] },
    [201],
  );
}

/** Path and query of a download URL (to be opened on the tenant origin through Caddy). */
export function downloadPath(downloadUrl: string): string {
  const u = new URL(downloadUrl, 'https://placeholder.localhost');
  return u.pathname + u.search + u.hash;
}

/**
 * Path of the personal download link of `recipient`, read in the notification mail they received
 * for `deposit` (the sender view and the API never return links). Waits for the mail.
 */
export async function recipientPath(deposit: { startedAt: number }, recipient: string): Promise<string> {
  const [mail] = await waitForMails(recipient, { after: deposit.startedAt });
  const link = linksOf(mail!).find((l) => new URL(l).pathname.startsWith('/d/'));
  if (!link) throw new Error(`no download link in the mail "${mail!.Subject}" to ${recipient}`);
  return downloadPath(link);
}
