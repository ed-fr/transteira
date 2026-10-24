// Typed client of the TransTeira REST API (/api/v1), built on the types generated from
// api/openapi.yaml (schema.ts). Browser dependencies (fetch, current language, CSRF token)
// are injected so that the client is testable in Node.
//
// - Accept: application/json, Accept-Language: current UI language, credentials: same-origin.
// - X-CSRF-Token on unsafe methods, from the in-memory store (csrf.svelte.ts); a csrfToken
//   member in a JSON answer (deposit session, admin profile) is handed to onCsrfToken.
// - application/problem+json errors become ApiProblem; no HTTP answer becomes NetworkError.
// - get/post/put/patch/delete are typed from the paths of the specification; request() is the
//   untyped primitive underneath. Typed PATCH bodies are sent as application/merge-patch+json.
// - Bodies are JSON, except a Blob (branding images), sent as-is with Content-Type = blob.type.
// - Optional hooks (admin application only; the public application sets none):
//   onUnauthenticated is called on 401 unauthenticated (never on invalid-credentials, which is a
//   form error); recoverCsrf is called on 403 csrf-invalid for an unsafe method and, when it
//   answers true, the request is retried exactly once with the refreshed token.
import type { components, paths } from './schema';

/** RFC 9457 Problem Details body, as defined by the specification. */
export type Problem = components['schemas']['Problem'];

/** Stable error code of a Problem. */
export type ProblemCode = components['schemas']['ProblemCode'];

/** One field error of a validation-failed Problem. */
export type ProblemFieldError = NonNullable<Problem['errors']>[number];

/** HTTP methods used by the API. */
export type Method = 'GET' | 'HEAD' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/** Query string values; undefined entries are omitted. */
export type QueryParams = Record<string, string | number | boolean | undefined>;

/** Options of one request. */
export interface RequestOptions {
  /** Query string parameters. */
  params?: QueryParams;
  /** JSON body (serialised with JSON.stringify), or a Blob sent as-is with its own type. */
  body?: unknown;
  /** Extra request headers (for example Idempotency-Key). */
  headers?: Record<string, string>;
  /** Aborts the request. */
  signal?: AbortSignal;
}

/** Successful response (2xx or 304). data is undefined when the body is not JSON. */
export interface ApiResponse<T> {
  status: number;
  data: T;
  headers: Headers;
}

/** Error response of the API, decoded from application/problem+json when present. */
export class ApiProblem extends Error {
  readonly status: number;
  readonly code: ProblemCode | undefined;
  readonly problem: Problem | undefined;

  constructor(status: number, problem: Problem | undefined) {
    super(problem?.detail ?? problem?.title ?? `HTTP ${status}`);
    this.name = 'ApiProblem';
    this.status = status;
    this.problem = problem;
    this.code = problem?.code;
  }

  /** Remaining attempts (wrong code or password). */
  get attemptsRemaining(): number | undefined {
    return this.problem?.attemptsRemaining;
  }

  /** Seconds before a new attempt (rate limited, locked). */
  get retryAfterSeconds(): number | undefined {
    return this.problem?.retryAfterSeconds;
  }

  /** Field errors (validation-failed). */
  get errors(): Problem['errors'] {
    return this.problem?.errors;
  }

  /** Size limit of a transfer (transfer-too-large). */
  get maxTransferBytes(): number | undefined {
    return this.problem?.maxTransferBytes;
  }

  /** Names of the refused files (blocked-file). */
  get files(): string[] | undefined {
    return this.problem?.files;
  }
}

/** The request did not get an HTTP response (offline, DNS failure, aborted). */
export class NetworkError extends Error {
  constructor(cause: unknown) {
    super('network error', { cause });
    this.name = 'NetworkError';
  }

  /** True when the request was aborted through its signal. */
  get aborted(): boolean {
    return this.cause instanceof DOMException && this.cause.name === 'AbortError';
  }
}

/** Injected dependencies of the client. */
export interface ApiClientDeps {
  /** fetch implementation (window.fetch in the browser). */
  fetch: typeof fetch;
  /** Base path of the API, default /api/v1. */
  baseUrl?: string;
  /** Current UI language, sent as Accept-Language. */
  language: () => string;
  /** Current CSRF token (memory only), sent as X-CSRF-Token on unsafe methods. */
  csrfToken: () => string | undefined;
  /** Receives the csrfToken member of a JSON answer (to update the in-memory store). */
  onCsrfToken?: (token: string) => void;
  /**
   * Called when an answer is 401 with the code unauthenticated (session missing or expired),
   * before the ApiProblem is thrown. Not called for invalid-credentials.
   */
  onUnauthenticated?: (problem: ApiProblem, method: Method, path: string) => void;
  /**
   * Called once when an unsafe request is refused with 403 csrf-invalid. When it resolves to
   * true (the CSRF token was refreshed), the request is sent again, once; a second refusal is
   * thrown. A rejection counts as false.
   */
  recoverCsrf?: () => Promise<boolean>;
}

// ---- Types derived from the specification -------------------------------------------------

type HttpMethodKey = 'get' | 'post' | 'put' | 'patch' | 'delete';

/** Paths of the specification having an operation for method M. */
export type PathsWith<M extends HttpMethodKey> = {
  [P in keyof paths]: paths[P][M] extends undefined | never ? never : P;
}[keyof paths];

/** Operation of path P for method M. */
export type Operation<P extends keyof paths, M extends HttpMethodKey> = NonNullable<paths[P][M]>;

type JsonContent<R> = R extends { content: { 'application/json': infer B } }
  ? B
  : R extends { content: { 'application/problem+json': unknown } }
    ? never
    : undefined;

/** JSON body of the success answers (2xx) of an operation; undefined for empty answers. */
export type SuccessBody<O> = O extends { responses: infer R }
  ? { [S in keyof R]: S extends 200 | 201 | 202 | 203 | 204 | 206 ? JsonContent<R[S]> : never }[keyof R]
  : never;

type ImageContent<C> = keyof C extends `image/${string}` ? Blob : never;

/** JSON (or JSON Merge Patch) request body of an operation; a Blob for image content. */
export type RequestBodyOf<O> = O extends { requestBody?: infer RB }
  ? [NonNullable<RB>] extends [never]
    ? never
    : NonNullable<RB> extends { content: { 'application/json': infer B } }
      ? B
      : NonNullable<RB> extends { content: { 'application/merge-patch+json': infer B } }
        ? B
        : NonNullable<RB> extends { content: infer C }
          ? ImageContent<C>
          : never
  : never;

/** Path parameters of an operation. */
export type PathParamsOf<O> = O extends { parameters: { path: infer P } } ? P : never;

/** Query parameters of an operation. */
export type QueryOf<O> = O extends { parameters: { query?: infer Q } } ? Q : never;

/** Options of a typed request: path parameters required when the path has some. */
export type TypedOptions<O> = Omit<RequestOptions, 'body' | 'params'> &
  ([PathParamsOf<O>] extends [never] | [undefined] ? { path?: never } : { path: PathParamsOf<O> }) &
  ([QueryOf<O>] extends [never] | [undefined] ? { params?: never } : { params?: QueryOf<O> & QueryParams }) &
  BodyOption<O>;

/** Body option of a typed request: required when the request body is, optional when it is not. */
type BodyOption<O> = [RequestBodyOf<O>] extends [never]
  ? { body?: never }
  : O extends { requestBody: unknown }
    ? { body: RequestBodyOf<O> }
    : { body?: RequestBodyOf<O> };

type Args<O> =
  Partial<TypedOptions<O>> extends TypedOptions<O> ? [options?: TypedOptions<O>] : [options: TypedOptions<O>];

/** API client. */
export interface ApiClient {
  /** Untyped request on a path relative to the API base. */
  request<T = unknown>(method: Method, path: string, options?: RequestOptions): Promise<ApiResponse<T>>;
  get<P extends PathsWith<'get'>>(
    path: P,
    ...args: Args<Operation<P, 'get'>>
  ): Promise<ApiResponse<SuccessBody<Operation<P, 'get'>>>>;
  post<P extends PathsWith<'post'>>(
    path: P,
    ...args: Args<Operation<P, 'post'>>
  ): Promise<ApiResponse<SuccessBody<Operation<P, 'post'>>>>;
  put<P extends PathsWith<'put'>>(
    path: P,
    ...args: Args<Operation<P, 'put'>>
  ): Promise<ApiResponse<SuccessBody<Operation<P, 'put'>>>>;
  patch<P extends PathsWith<'patch'>>(
    path: P,
    ...args: Args<Operation<P, 'patch'>>
  ): Promise<ApiResponse<SuccessBody<Operation<P, 'patch'>>>>;
  delete<P extends PathsWith<'delete'>>(
    path: P,
    ...args: Args<Operation<P, 'delete'>>
  ): Promise<ApiResponse<SuccessBody<Operation<P, 'delete'>>>>;
}

const SAFE_METHODS: ReadonlySet<Method> = new Set(['GET', 'HEAD']);

/** Builds the URL of path (relative to the API base) with its query string. */
export function buildUrl(baseUrl: string, path: string, params?: QueryParams): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value !== undefined) {
      query.append(key, String(value));
    }
  }
  const qs = query.toString();
  return baseUrl + path + (qs === '' ? '' : `?${qs}`);
}

/**
 * Substitutes {name} segments of a specification path with URI-encoded values.
 * Throws when a parameter is missing, so that no request goes to a literal "{name}" path.
 */
export function expandPath(template: string, values: Record<string, string | number> | undefined): string {
  return template.replace(/\{([^}]+)\}/g, (_whole, name: string) => {
    const value = values?.[name];
    if (value === undefined || value === '') {
      throw new Error(`missing path parameter ${name}`);
    }
    return encodeURIComponent(String(value));
  });
}

function isMediaType(contentType: string, mediaType: string): boolean {
  return contentType.split(';')[0]?.trim().toLowerCase() === mediaType;
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return undefined;
  }
}

function asProblem(body: unknown): Problem | undefined {
  return typeof body === 'object' && body !== null && !Array.isArray(body) ? (body as Problem) : undefined;
}

/** Creates an API client. */
export function createApiClient(deps: ApiClientDeps): ApiClient {
  const baseUrl = deps.baseUrl ?? '/api/v1';

  async function request<T>(
    method: Method,
    path: string,
    options: RequestOptions = {},
  ): Promise<ApiResponse<T>> {
    return send<T>(method, path, options, false);
  }

  async function recovered(): Promise<boolean> {
    try {
      return deps.recoverCsrf !== undefined && (await deps.recoverCsrf());
    } catch {
      return false;
    }
  }

  async function send<T>(
    method: Method,
    path: string,
    options: RequestOptions,
    retried: boolean,
  ): Promise<ApiResponse<T>> {
    const headers = new Headers(options.headers);
    headers.set('Accept', 'application/json');
    headers.set('Accept-Language', deps.language());
    const token = deps.csrfToken();
    if (!SAFE_METHODS.has(method) && token !== undefined && token !== '') {
      headers.set('X-CSRF-Token', token);
    }
    let body: string | Blob | undefined;
    if (options.body instanceof Blob) {
      if (!headers.has('Content-Type') && options.body.type !== '') {
        headers.set('Content-Type', options.body.type);
      }
      body = options.body;
    } else if (options.body !== undefined) {
      if (!headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
      }
      body = JSON.stringify(options.body);
    }
    let response: Response;
    try {
      response = await deps.fetch(buildUrl(baseUrl, path, options.params), {
        method,
        headers,
        body: body ?? null,
        credentials: 'same-origin',
        signal: options.signal ?? null,
      });
    } catch (err) {
      throw new NetworkError(err);
    }
    const contentType = response.headers.get('Content-Type') ?? '';
    if (!response.ok && response.status !== 304) {
      const problem = isMediaType(contentType, 'application/problem+json')
        ? asProblem(await readJson(response))
        : undefined;
      const error = new ApiProblem(response.status, problem);
      if (error.status === 401 && error.code === 'unauthenticated') {
        deps.onUnauthenticated?.(error, method, path);
      } else if (
        error.status === 403 &&
        error.code === 'csrf-invalid' &&
        !SAFE_METHODS.has(method) &&
        !retried &&
        (await recovered())
      ) {
        return send<T>(method, path, options, true);
      }
      throw error;
    }
    let data: unknown;
    if (method !== 'HEAD' && isMediaType(contentType, 'application/json')) {
      data = await readJson(response);
      const csrfToken = (data as { csrfToken?: unknown } | undefined)?.csrfToken;
      if (typeof csrfToken === 'string' && csrfToken !== '' && deps.onCsrfToken !== undefined) {
        deps.onCsrfToken(csrfToken);
      }
    }
    return { status: response.status, data: data as T, headers: response.headers };
  }

  function typed(method: Method) {
    return (path: string, options: RequestOptions & { path?: Record<string, string | number> } = {}) => {
      const { path: pathParams, ...rest } = options;
      if (method === 'PATCH' && rest.body !== undefined) {
        // Every PATCH operation of the API takes a JSON Merge Patch (RFC 7396).
        rest.headers = { 'Content-Type': 'application/merge-patch+json', ...rest.headers };
      }
      return request(method, expandPath(path, pathParams), rest);
    };
  }

  return {
    request,
    get: typed('GET'),
    post: typed('POST'),
    put: typed('PUT'),
    patch: typed('PATCH'),
    delete: typed('DELETE'),
  } as ApiClient;
}
