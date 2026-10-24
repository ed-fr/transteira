// Direct HTTP client of the server under test (bypassing Caddy), used to seed data and to set
// up or check state around browser scenarios. Requests go to <listenHost()>:<server port>
// (127.0.0.1, or the Docker bridge gateway on Linux) with the Host header of the wanted tenant
// or admin host and X-Real-IP: 127.0.0.1, since that source address is a trusted proxy in the
// e2e configuration (a trusted peer without client IP is refused).
//
// Admin calls carry what the browser would send: the session cookie, the CSRF token, and the
// Origin / Sec-Fetch-Site headers checked on every unsafe admin request.
import http from 'node:http';
import { HOSTS, ORIGINS, listenHost } from './env';

/** Response of a request. */
export interface ApiResponse<T = unknown> {
  status: number;
  headers: http.IncomingHttpHeaders;
  /** Parsed JSON body, undefined when the body is not JSON. */
  json: T;
  /** Raw body. */
  body: Buffer;
  text: string;
}

/** Options of request. */
export interface RequestOptions {
  /** Host header (default: admin host). */
  host?: string;
  /** JSON body (serialized) or raw bytes (sent as is; set Content-Type in headers). */
  body?: unknown;
  headers?: Record<string, string>;
  /** Client IP announced in X-Real-IP (default 127.0.0.1, inside the tenants' internal ranges). */
  clientIp?: string;
}

/** Browser origin for a host name (the Origin header of a same-origin request). */
export function originOf(host: string): string {
  const entry = Object.entries(HOSTS).find(([, h]) => h === host);
  return entry ? ORIGINS[entry[0] as keyof typeof ORIGINS] : `https://${host}`;
}

/** Sends one request to the server on listenHost():port. */
export function request<T = unknown>(
  port: number,
  method: string,
  path: string,
  opts: RequestOptions = {},
): Promise<ApiResponse<T>> {
  const host = opts.host ?? HOSTS.admin;
  let data: Buffer | undefined;
  const headers: Record<string, string | number> = { Host: host, 'X-Real-IP': opts.clientIp ?? '127.0.0.1' };
  if (Buffer.isBuffer(opts.body)) {
    data = opts.body;
  } else if (opts.body !== undefined) {
    data = Buffer.from(JSON.stringify(opts.body));
    headers['Content-Type'] = 'application/json';
  }
  if (data) headers['Content-Length'] = data.length;
  Object.assign(headers, opts.headers);
  return new Promise((resolve, reject) => {
    const req = http.request({ host: listenHost(), port, method, path, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks);
        const text = body.toString('utf8');
        let json: unknown;
        try {
          json = JSON.parse(text);
        } catch {
          json = undefined;
        }
        resolve({ status: res.statusCode ?? 0, headers: res.headers, json: json as T, body, text });
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

/** Value of the admin session cookie set by a response, if any. */
export function adminCookieOf(res: ApiResponse): string | undefined {
  const cookies = res.headers['set-cookie'] ?? [];
  let value: string | undefined;
  for (const c of cookies) {
    const m = /^__Host-tt_admin=([^;]*)/.exec(c);
    if (m) value = m[1];
  }
  return value;
}

/** An admin API session (cookie value and CSRF token). */
export interface AdminSession {
  cookie: string;
  csrf: string;
}

/** Headers of a same-origin request from the admin interface. */
function sameOrigin(): Record<string, string> {
  return { Origin: ORIGINS.admin, 'Sec-Fetch-Site': 'same-origin' };
}

/** Admin API client bound to a server port and, once signed in, to a session. */
export class AdminApi {
  constructor(
    readonly port: number,
    public session?: AdminSession,
  ) {}

  /** Calls /api/v1<path> on the admin host as the current session. */
  async call<T = unknown>(method: string, path: string, body?: unknown): Promise<ApiResponse<T>> {
    const headers: Record<string, string> = sameOrigin();
    if (this.session) {
      headers.Cookie = `__Host-tt_admin=${this.session.cookie}`;
      headers['X-CSRF-Token'] = this.session.csrf;
    }
    const res = await request<T>(this.port, method, `/api/v1${path}`, { body, headers });
    const cookie = adminCookieOf(res);
    const csrf = (res.json as { csrfToken?: unknown } | undefined)?.csrfToken;
    if (cookie !== undefined)
      this.session = { cookie, csrf: typeof csrf === 'string' ? csrf : (this.session?.csrf ?? '') };
    else if (this.session && typeof csrf === 'string') this.session.csrf = csrf;
    return res;
  }

  /** Like call, but throws unless the status is one of expected (default 2xx). */
  async ok<T = unknown>(method: string, path: string, body?: unknown, expected?: number[]): Promise<T> {
    const res = await this.call<T>(method, path, body);
    const good = expected ? expected.includes(res.status) : res.status >= 200 && res.status < 300;
    if (!good) throw new Error(`${method} ${path} -> ${res.status} ${res.text.slice(0, 500)}`);
    return res.json;
  }

  /**
   * Signs in with a password, then a TOTP code when the server asks for one (totp is called
   * lazily, so that no TOTP step is consumed for an account without second factor).
   */
  async login(username: string, password: string, totp?: () => Promise<string>): Promise<void> {
    this.session = undefined;
    const res = await this.ok<{ status: string }>('POST', '/admin/auth/login', { username, password });
    if (res.status === 'authenticated') return;
    if (res.status !== 'totp_required' || !totp) throw new Error(`unexpected login state ${res.status}`);
    await this.ok('POST', '/admin/auth/totp', { code: await totp() });
  }
}
