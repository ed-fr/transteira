// State machine of the express secret page /x (CLAUDE.md section 22.2, version 2.3): one text
// area, one duration, one button, one link. No session, no address, no CSRF token: POST
// /express-secrets is anonymous (the API client still sends its usual headers, which the server
// ignores there).
//
// Steps:
//   form → working (seal, createExpressSecret) → done
//   working → form (refused: nothing was created; a new submission draws a new K)
//   done → form ("Create another secret", the page hidden or left: forgetResult)
// The link (with K) is composed by the page from the token of the answer, shown once on the done
// step and forgotten when the step is left. The text leaves the page state as soon as the secret
// is created, and the bytes of K are wiped once the link is built or the creation refused. Neither
// the text, nor K, nor the link is ever written to the URL, a storage, a log or the console
// (threat model T-399).
import type { ApiClient } from '../../shared/api/client';
import { problemMessage, type Translator } from '../../shared/api/problem';
import type { components } from '../../shared/api/schema';
import { codePoints } from './create';
import {
  classifyExpressError,
  defaultExpressDuration,
  expressDurations,
  expressFailureMessage,
  expressFeatures,
  expressLink,
  expressMaxChars,
  expressOffered,
  invalidExpressFields,
  sealExpress,
  validateExpress,
  type ExpressDuration,
  type ExpressErrors,
  type ExpressFailure,
  type ExpressFeatures,
  type ExpressField,
  type SealExpressOptions,
} from './express';

/** Public tenant description (GET /tenant). */
type PublicTenant = components['schemas']['PublicTenant'];

/** What the flow reads from the page (the tenant may be fetched again on a language change). */
export interface ExpressHost {
  readonly tenant: PublicTenant;
}

/** Browser dependencies of the express flow. */
export interface ExpressFlowDeps {
  api: Pick<ApiClient, 'post'>;
  tr: Translator;
  announce: (message: string, politeness?: 'polite' | 'assertive') => void;
  /** Origin of the page (the FQDN of the tenant), for the link. */
  origin: () => string;
  /** Formats a clock time (epoch milliseconds), for the end of a rate limit. */
  formatTime: (epochMs: number) => string;
  /** Clock (rate limiting). */
  now?: () => number;
  /** Options of the sealing (tests). */
  seal?: SealExpressOptions;
}

/** Step of the page. */
export type ExpressStep = 'form' | 'working' | 'done';

/** Phase of the working step. */
export type ExpressPhase = 'sealing' | 'creating';

/** The express secret creation of one /x page. Fields are reactive ($state) when read in components. */
export class ExpressSecretFlow {
  step = $state<ExpressStep>('form');
  phase = $state<ExpressPhase | undefined>(undefined);
  text = $state('');
  expiresIn = $state<ExpressDuration | undefined>(undefined);
  errors = $state.raw<ExpressErrors>({});
  /** Incremented at each refusal: the form focuses its error summary or its error message. */
  refusals = $state(0);
  failure = $state.raw<ExpressFailure | undefined>(undefined);
  /** Rate limited until this time (epoch milliseconds). */
  retryAt = $state<number | undefined>(undefined);
  /** Full link (with K), shown once on the done step. */
  link = $state<string | undefined>(undefined);
  /** Expiry of the created secret, on the done step. */
  expiresAt = $state<string | undefined>(undefined);

  readonly #host: ExpressHost;
  readonly #deps: ExpressFlowDeps;
  readonly #now: () => number;

  constructor(host: ExpressHost, deps: ExpressFlowDeps) {
    this.#host = host;
    this.#deps = deps;
    this.#now = deps.now ?? Date.now;
    this.expiresIn = defaultExpressDuration(this.durations);
  }

  // ---- Derived values ---------------------------------------------------------------------

  /** Express rules of the tenant (undefined before 2.3). */
  get features(): ExpressFeatures | undefined {
    return expressFeatures(this.#host.tenant);
  }

  /** The page offers the form. */
  get offered(): boolean {
    return expressOffered(this.features);
  }

  /** Offered durations, in the order of the format. */
  get durations(): ExpressDuration[] {
    return expressDurations(this.features);
  }

  /** Largest text, in code points. */
  get maxChars(): number {
    return expressMaxChars(this.features);
  }

  /** Number of code points of the text (counter). */
  get textLength(): number {
    return codePoints(this.text);
  }

  /** The text is longer than allowed (counter shown as an error). */
  get overLimit(): boolean {
    return this.textLength > this.maxChars;
  }

  /** Fields with an error, in display order. */
  get invalidFields(): ExpressField[] {
    return invalidExpressFields(this.errors);
  }

  /** The form is being processed. */
  get busy(): boolean {
    return this.step === 'working';
  }

  /** Text of the refusal, undefined without one. */
  get errorText(): string | undefined {
    const failure = this.failure;
    if (failure === undefined) return undefined;
    const time = this.retryAt === undefined ? undefined : this.#deps.formatTime(this.retryAt);
    const message = expressFailureMessage(failure, this.#host.tenant.name, time);
    if (message === undefined) {
      return problemMessage(this.#deps.tr, failure.kind === 'error' ? failure.cause : undefined);
    }
    return this.#deps.tr.t(message.key, message.params);
  }

  /** Seconds before a new attempt is allowed (0 when not rate limited). */
  secondsBeforeRetry(now: number = this.#now()): number {
    return this.retryAt === undefined ? 0 : Math.max(0, Math.ceil((this.retryAt - now) / 1000));
  }

  // ---- Actions ----------------------------------------------------------------------------

  /** Checks, seals and creates the secret, then composes its link. */
  async submit(): Promise<void> {
    if (this.step !== 'form' || this.secondsBeforeRetry() > 0) return;
    const text = this.text;
    const expiresIn = this.expiresIn;
    this.failure = undefined;
    const errors = validateExpress({ text, expiresIn }, this.durations, this.maxChars);
    if (invalidExpressFields(errors).length > 0 || expiresIn === undefined) {
      this.errors = errors;
      this.refusals++;
      return;
    }
    this.errors = {};
    this.retryAt = undefined;
    this.step = 'working';
    this.phase = 'sealing';
    let sealed;
    try {
      sealed = await sealExpress(text, expiresIn, this.#deps.seal);
    } catch {
      this.#refused({ kind: 'seal' });
      return;
    }
    this.phase = 'creating';
    let created;
    try {
      created = (await this.#deps.api.post('/express-secrets', { body: sealed.body })).data;
    } catch (err) {
      // Nothing was created: a new submission draws a new K.
      sealed.key.fill(0);
      this.#refused(classifyExpressError(err));
      return;
    }
    this.link = expressLink(this.#deps.origin(), created.token, sealed.key);
    // The link string carries K from now on: its bytes are no longer needed.
    sealed.key.fill(0);
    this.expiresAt = created.expiresAt;
    // The secret is sealed and stored: its plaintext leaves the page state.
    this.text = '';
    this.phase = undefined;
    this.step = 'done';
    this.#deps.announce(this.#deps.tr.t('secretExpress.done.announce'));
  }

  /** "Create another secret": forgets the link and shows an empty form. */
  createAnother(): void {
    this.#clearResult();
    this.text = '';
    this.errors = {};
    this.failure = undefined;
    this.expiresIn = defaultExpressDuration(this.durations);
  }

  /**
   * The done screen is left (page hidden or left): the link is forgotten, so that "it cannot be
   * displayed again" stays true.
   */
  forgetResult(): void {
    if (this.step === 'done') this.#clearResult();
  }

  // ---- Internals --------------------------------------------------------------------------

  #clearResult(): void {
    this.link = undefined;
    this.expiresAt = undefined;
    if (this.step === 'done') this.step = 'form';
  }

  /** Back to the form with the reason (nothing was created); the text is kept to try again. */
  #refused(failure: ExpressFailure): void {
    if (failure.kind === 'rate-limited' && failure.retryAfterSeconds !== undefined) {
      this.retryAt = this.#now() + failure.retryAfterSeconds * 1000;
    }
    this.phase = undefined;
    this.step = 'form';
    this.failure = failure;
    this.refusals++;
  }
}
