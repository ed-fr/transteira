// State machine of the creation of a one-time secret in the public application (CLAUDE.md
// section 22.1, V2.1): the "Share a secret" tab of the deposit form. It uses the deposit session
// of the deposit flow (same API client, same CSRF token) and hands maintenance and an expired
// session back to it (DepositFlow.sessionError), so that the identification is never duplicated.
//
// Steps:
//   form → working (seal, createSecret, uploadSecretFile, sendSecret) → done
//   working → form (refused at creation: nothing was created; a new submission draws a new K)
//   working → retry (created, but the upload or the send failed) → working (same bytes) | form
//   done → form ("Create another secret", or the done screen left: forgetResult)
// The link (with K) is shown once on the done step and forgotten when the step is left; the form
// is emptied as soon as the secret is created. The bytes of K are wiped once they are no longer
// needed: when the link is built or the mail sent, and when a secret is given up. An explicit end
// of the deposit session forgets everything (reset); a merely expired one keeps the draft.
import { ApiProblem, type ApiClient } from '../../shared/api/client';
import { problemMessage, type Translator } from '../../shared/api/problem';
import type { components } from '../../shared/api/schema';
import {
  codePoints,
  effectiveRecipient,
  emailOnly,
  emptySecretForm,
  fragmentKey,
  invalidSecretFields,
  mapSecretErrors,
  maxPlainFileSize,
  passphraseRequired,
  sealSecretForm,
  secretLink,
  secretsOffered,
  validateSecret,
  type Message,
  type SealSecretOptions,
  type SecretCreator,
  type SecretDelivery,
  type SecretErrors,
  type SecretFeatures,
  type SecretField,
  type SecretFile,
  type SecretForm,
} from './create';

/** Public tenant description (GET /tenant). */
type PublicTenant = components['schemas']['PublicTenant'];
/** A secret as its creator sees it (uploadSecretFile, sendSecret). */
type Secret = components['schemas']['Secret'];

/** What the secret flow needs from the deposit flow (DepositFlow satisfies it). */
export interface SecretHost {
  readonly tenant: PublicTenant;
  /** Invited external depositor. */
  readonly isExternal: boolean;
  /** Inviter of an external depositor. */
  readonly invitedBy: string | undefined;
  readonly isDropLink: boolean;
  readonly isReply: boolean;
  /** Handles maintenance and an expired session; true when handled. */
  sessionError(err: unknown): boolean;
  /** Calls listener when the depositor ends the session explicitly ("End session"). */
  onSessionEnd(listener: () => void): () => void;
}

/** Browser dependencies of the secret flow. */
export interface SecretFlowDeps {
  api: ApiClient;
  tr: Translator;
  announce: (message: string, politeness?: 'polite' | 'assertive') => void;
  /** Origin of the page (the FQDN of the tenant), for the link. */
  origin: () => string;
  /** Clock (rate limiting). */
  now?: () => number;
  /** Options of the sealing (tests). */
  seal?: SealSecretOptions;
}

/** Step of the secret tab. */
export type SecretStep = 'form' | 'working' | 'retry' | 'done';

/** Phase of the working step. */
export type SecretPhase = 'sealing' | 'creating' | 'uploading' | 'sending';

/** Error displayed on the form or retry step: a translated message or an API error to describe. */
export type SecretStepError = { message: Message } | { cause: unknown };

/** A created secret whose file upload or mail is not done yet. */
interface Pending {
  id: string;
  token: string;
  key: Uint8Array<ArrayBuffer>;
  delivery: SecretDelivery;
  recipient: string | undefined;
  file: Uint8Array<ArrayBuffer> | undefined;
  uploaded: boolean;
  uploadTried: boolean;
  sendTried: boolean;
  expiresAt: string | undefined;
}

const DISABLED: SecretFeatures = {
  enabled: false,
  durations: [],
  fileAllowed: false,
  fileMaxBytes: 0,
  emailAllowed: false,
};

function isProblem(err: unknown, code?: string): err is ApiProblem {
  return err instanceof ApiProblem && (code === undefined || err.code === code);
}

/** The secret creation of one deposit page. Fields are reactive ($state) when read in components. */
export class SecretCreateFlow {
  step = $state<SecretStep>('form');
  phase = $state<SecretPhase | undefined>(undefined);
  form = $state<SecretForm>() as SecretForm;
  errors = $state.raw<SecretErrors>({});
  /** Incremented at each refusal: the form focuses its error summary. */
  refusals = $state(0);
  stepError = $state.raw<SecretStepError | undefined>(undefined);
  /** Rate limited until this time (epoch milliseconds). */
  retryAt = $state<number | undefined>(undefined);
  /** Full link of a link delivery, shown once on the done step. */
  link = $state<string | undefined>(undefined);
  /** Recipient of an e-mail delivery, on the done step. */
  sentTo = $state<string | undefined>(undefined);
  /** Expiry of the created secret, on the done step. */
  expiresAt = $state<string | undefined>(undefined);
  /** The created secret has a file (done step). */
  doneWithFile = $state(false);

  readonly #host: SecretHost;
  readonly #deps: SecretFlowDeps;
  readonly #now: () => number;
  #pending: Pending | undefined;
  #email: string | undefined;

  constructor(host: SecretHost, deps: SecretFlowDeps) {
    this.#host = host;
    this.#deps = deps;
    this.#now = deps.now ?? Date.now;
    this.form = emptySecretForm(this.creator);
    // An explicit end of the session is another depositor to come: nothing is kept.
    host.onSessionEnd(() => this.reset());
  }

  // ---- Derived values ---------------------------------------------------------------------

  /** Rules of the tenant (a disabled module when absent). */
  get features(): SecretFeatures {
    return this.#host.tenant.features?.secrets ?? DISABLED;
  }

  /** The creator as the rules see it. */
  get creator(): SecretCreator {
    return { features: this.features, external: this.#host.isExternal, inviter: this.#host.invitedBy };
  }

  /** The "Share a secret" tab is offered (not to drop link or reply sessions). */
  get offered(): boolean {
    return (
      !this.#host.isDropLink && !this.#host.isReply && secretsOffered(this.features, this.#host.isExternal)
    );
  }

  /** E-mail delivery to the inviter only (invited external). */
  get emailOnly(): boolean {
    return emailOnly(this.creator);
  }

  /** The delivery choice is shown (e-mail allowed and not imposed). */
  get deliveryChoice(): boolean {
    return !this.emailOnly && this.features.emailAllowed;
  }

  /** The delivery the form will use. */
  get delivery(): SecretDelivery {
    return this.emailOnly || (this.deliveryChoice && this.form.delivery === 'email') ? 'email' : 'link';
  }

  /** Recipient imposed on an invited external (the inviter). */
  get imposedRecipient(): string | undefined {
    return this.emailOnly ? effectiveRecipient(this.form, this.creator) : undefined;
  }

  /** The passphrase is mandatory for the chosen delivery. */
  get passphraseRequired(): boolean {
    return passphraseRequired({ ...this.form, delivery: this.delivery }, this.creator);
  }

  /** Number of code points of the text (counter). */
  get textLength(): number {
    return codePoints(this.form.text);
  }

  /** Largest plaintext file accepted (hint). */
  get maxFileBytes(): number {
    return maxPlainFileSize(this.features.fileMaxBytes);
  }

  /** Fields with an error, in display order. */
  get invalidFields(): SecretField[] {
    return invalidSecretFields(this.errors);
  }

  /** The form is being processed. */
  get busy(): boolean {
    return this.step === 'working';
  }

  /** Text of the step error. */
  get errorText(): string | undefined {
    const e = this.stepError;
    if (e === undefined) return undefined;
    return 'message' in e
      ? this.#deps.tr.t(e.message.key, e.message.params)
      : problemMessage(this.#deps.tr, e.cause);
  }

  // ---- Actions ----------------------------------------------------------------------------

  /** Keeps the first chosen file (a secret holds at most one). */
  setFile(files: readonly SecretFile[]): void {
    const file = files[0];
    if (file === undefined || this.busy) return;
    this.form.file = file;
    this.#clearError('file');
    this.#clearError('text');
  }

  /** Removes the file. */
  removeFile(): void {
    if (this.busy) return;
    this.form.file = undefined;
    this.#clearError('file');
  }

  /** Checks, seals and creates the secret, then uploads its file and mails it as needed. */
  async submit(): Promise<void> {
    if (this.step !== 'form' || this.#now() < (this.retryAt ?? 0)) return;
    const form: SecretForm = { ...this.form, delivery: this.delivery };
    const creator = this.creator;
    this.stepError = undefined;
    const errors = validateSecret(form, creator);
    if (invalidSecretFields(errors).length > 0) {
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
      sealed = await sealSecretForm(form, creator, this.#deps.seal);
    } catch {
      this.#refused({ message: { key: 'secretCreate.error.sealFailed' } });
      return;
    }
    this.phase = 'creating';
    let created;
    try {
      created = (await this.#deps.api.post('/secrets', { body: sealed.body })).data;
    } catch (err) {
      // Nothing was created: a new submission draws a new K.
      sealed.key.fill(0);
      this.#createError(err);
      return;
    }
    this.#pending = {
      id: created.id,
      token: created.token,
      key: sealed.key,
      delivery: sealed.body.delivery,
      recipient: sealed.body.recipient,
      file: sealed.file,
      uploaded: sealed.file === undefined,
      uploadTried: false,
      sendTried: false,
      expiresAt: created.expiresAt,
    };
    await this.#complete();
  }

  /** Retries the failed upload (same bytes) or mail of the created secret. */
  async retry(): Promise<void> {
    if (this.step !== 'retry' || this.#pending === undefined || this.#now() < (this.retryAt ?? 0)) return;
    this.stepError = undefined;
    this.retryAt = undefined;
    this.step = 'working';
    await this.#complete();
  }

  /** Gives up the incomplete secret (purged by the server after one hour) and edits the form again. */
  abandon(): void {
    if (this.step !== 'retry') return;
    this.#dropPending();
    this.stepError = undefined;
    this.retryAt = undefined;
    this.step = 'form';
  }

  /** "Create another secret": forgets the link and shows an empty form. */
  createAnother(): void {
    this.#clearResult();
    this.form = emptySecretForm(this.creator);
  }

  /**
   * The done screen is left (another tab, another step, page left): the link is forgotten, so
   * that "it cannot be displayed again" stays true.
   */
  forgetResult(): void {
    if (this.step === 'done') this.#clearResult();
  }

  /** Forgets everything (another depositor). */
  reset(): void {
    this.#dropPending();
    this.#clearResult();
    this.step = 'form';
    this.phase = undefined;
    this.form = emptySecretForm(this.creator);
    this.errors = {};
    this.stepError = undefined;
    this.retryAt = undefined;
  }

  /**
   * Follows the deposit session: when it ends, the link of a created secret is forgotten; when
   * another address signs in, everything is (the form and an incomplete secret, which only its
   * creator may complete). An expired session of the same address keeps the form and the
   * incomplete secret.
   */
  syncSession(email: string | undefined): void {
    if (email === undefined) {
      if (this.step === 'done') this.#clearResult();
      return;
    }
    if (this.#email !== undefined && this.#email.toLowerCase() !== email.toLowerCase()) this.reset();
    this.#email = email;
  }

  /** Seconds before a new attempt is allowed (0 when not rate limited). */
  secondsBeforeRetry(now: number = this.#now()): number {
    return this.retryAt === undefined ? 0 : Math.max(0, Math.ceil((this.retryAt - now) / 1000));
  }

  // ---- Internals --------------------------------------------------------------------------

  /** Uploads the file and sends the mail still to do, then shows the done step. */
  async #complete(): Promise<void> {
    const p = this.#pending as Pending;
    if (!p.uploaded && p.file !== undefined) {
      this.phase = 'uploading';
      const retried = p.uploadTried;
      p.uploadTried = true;
      try {
        const answer = await this.#deps.api.request<Secret>(
          'PUT',
          `/secrets/${encodeURIComponent(p.id)}/file`,
          {
            body: new Blob([p.file], { type: 'application/octet-stream' }),
          },
        );
        p.expiresAt = answer.data.expiresAt ?? p.expiresAt;
      } catch (err) {
        // A retried upload refused as a conflict was stored by the lost answer of the previous one.
        if (!(retried && isProblem(err, 'state-conflict'))) {
          this.#completionError(err);
          return;
        }
      }
      p.uploaded = true;
    }
    if (p.delivery === 'email') {
      this.phase = 'sending';
      const retried = p.sendTried;
      p.sendTried = true;
      try {
        const answer = await this.#deps.api.post('/secrets/{secretId}/send', {
          path: { secretId: p.id },
          body: { secretToken: p.token, fragmentKey: fragmentKey(p.key) },
        });
        p.expiresAt = answer.data.expiresAt ?? p.expiresAt;
      } catch (err) {
        // Same for a retried send: the secret was activated and its mail queued.
        if (!(retried && isProblem(err, 'state-conflict'))) {
          this.#completionError(err);
          return;
        }
      }
    }
    this.#done(p);
  }

  #done(p: Pending): void {
    this.#pending = undefined;
    this.link = p.delivery === 'link' ? secretLink(this.#deps.origin(), p.token, p.key) : undefined;
    // The link string (or the mail) carries K from now on: its bytes are no longer needed.
    p.key.fill(0);
    this.sentTo = p.delivery === 'email' ? p.recipient : undefined;
    this.expiresAt = p.expiresAt;
    this.doneWithFile = p.file !== undefined;
    this.phase = undefined;
    // The secret is sealed and stored: its plaintext leaves the page state.
    this.form = emptySecretForm(this.creator);
    this.errors = {};
    this.step = 'done';
    this.#deps.announce(this.#deps.tr.t('secretCreate.done.announce'));
  }

  /** Forgets the incomplete secret and wipes its key. */
  #dropPending(): void {
    this.#pending?.key.fill(0);
    this.#pending = undefined;
  }

  #clearResult(): void {
    this.link = undefined;
    this.sentTo = undefined;
    this.expiresAt = undefined;
    this.doneWithFile = false;
    if (this.step === 'done') this.step = 'form';
  }

  #clearError(field: SecretField): void {
    if (this.errors[field] !== undefined) {
      const next = { ...this.errors };
      delete next[field];
      this.errors = next;
    }
  }

  /** Back to the form with an error (nothing was created). */
  #refused(error: SecretStepError | undefined, errors: SecretErrors = {}): void {
    this.phase = undefined;
    this.step = 'form';
    this.stepError = error;
    this.errors = errors;
    this.refusals++;
  }

  /** Errors common to every request; true when handled. */
  #commonError(err: unknown): boolean {
    if (this.#host.sessionError(err)) {
      this.stepError = undefined;
      return true;
    }
    if (isProblem(err, 'rate-limited') || isProblem(err, 'secret-limit-reached')) {
      const seconds = err.retryAfterSeconds;
      this.retryAt = seconds === undefined ? undefined : this.#now() + seconds * 1000;
    }
    return false;
  }

  #createError(err: unknown): void {
    if (this.#commonError(err)) {
      this.phase = undefined;
      this.step = 'form';
      return;
    }
    const general: SecretStepError = { cause: err };
    if (isProblem(err, 'validation-failed') || isProblem(err, 'recipient-domain-refused')) {
      let mapped = mapSecretErrors(err.errors, (key) => this.#deps.tr.has(key));
      if (err.code === 'recipient-domain-refused' && mapped.recipient === undefined && !this.emailOnly) {
        mapped = { ...mapped, recipient: { key: 'secretCreate.recipient.domainRefused' } };
      }
      const visible = this.#visible(mapped);
      this.#refused(invalidSecretFields(visible).length === 0 ? general : undefined, visible);
    } else if (isProblem(err, 'secret-passphrase-required')) {
      this.#refused(undefined, { passphrase: { key: 'secretCreate.passphrase.requiredByEmail' } });
    } else if (isProblem(err, 'secret-email-not-allowed') && this.deliveryChoice) {
      this.#refused(undefined, { delivery: { key: 'secretCreate.delivery.emailNotAllowed' } });
    } else if (isProblem(err, 'secret-file-not-allowed')) {
      this.#refused(undefined, { file: { key: 'secretCreate.file.notAllowed' } });
    } else if (isProblem(err, 'secret-file-too-large')) {
      const max = err.maxTransferBytes ?? this.features.fileMaxBytes;
      this.#refused(undefined, {
        file: { key: 'secretCreate.file.tooLarge', params: { max: maxPlainFileSize(max) } },
      });
    } else if (isProblem(err, 'secret-duration-not-offered')) {
      this.#refused(undefined, { expiresIn: { key: 'fieldErrors.not-allowed' } });
    } else {
      this.#refused(general);
    }
  }

  /** Drops the errors of fields the form does not show (delivery and recipient of an external). */
  #visible(errors: SecretErrors): SecretErrors {
    if (!this.emailOnly && this.deliveryChoice) return errors;
    const out = { ...errors };
    delete out.delivery;
    if (this.emailOnly) delete out.recipient;
    return out;
  }

  /** The upload or the send of a created secret failed. */
  #completionError(err: unknown): void {
    this.phase = undefined;
    if (isProblem(err, 'not-found')) {
      // Purged (pending for more than one hour) or gone: create it again.
      this.#dropPending();
      this.#refused({ message: { key: 'secretCreate.error.pendingGone' } });
      return;
    }
    if (this.#commonError(err)) {
      this.step = 'retry';
      return;
    }
    this.stepError = { cause: err };
    this.step = 'retry';
    this.refusals++;
  }
}
