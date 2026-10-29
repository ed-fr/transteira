// State machine of the public deposit page (CLAUDE.md sections 7, 8, 9; step 15 design,
// "Public screens" item 1). The screens (*.svelte in this folder) only render the state and call
// the actions below; every browser dependency is injected so that the flow is unit tested in
// Node with a fake API (fetch) and a fake upload engine.
//
// Steps:
//   loading → (maintenance | email | form | resume | error)
//   email → code (202) | form (201)          code → form | email (code exhausted)
//   form → upload → finalizing → done        upload → form (cancelled)
//   resume (reload during an upload) → upload | form
//   reload during the antivirus analysis → finalizing (polling only) → done; reload once the
//   transfer is decided → done
// The download link of a transfer is never shown to the depositor (design decision D2): the
// done step is a recap only.
import { ApiProblem, NetworkError, type ApiClient } from '../../shared/api/client';
import { problemMessage, type Translator } from '../../shared/api/problem';
import { languageValues, type components } from '../../shared/api/schema';
import {
  conflictDelay,
  UploadError,
  type UploadAnnouncement,
  type UploadEngine,
  type UploadFileSpec,
  type UploadSnapshot,
} from '../../shared/upload/engine';
import {
  IdempotencyKey,
  uploadSpecs,
  type FinalizeOptions,
  type FinalizeOutcome,
  type SenderTransfer,
} from '../../shared/upload/finalize';
import {
  fingerprint,
  matchFiles,
  type FileFingerprint,
  type ResumeRecord,
  type ResumeStore,
} from '../../shared/upload/resume-store';
import {
  addFiles,
  defaultLevel,
  selectableLevels,
  effectiveDeleteAfterFirst,
  effectiveRecipientVerification,
  effectiveExpiryDays,
  invalidFields,
  isEmail,
  keepExpiry,
  keepMaxDownloads,
  levelByKey,
  mapRecipientDomainErrors,
  mapRuleErrors,
  mapServerErrors,
  parseMaxDownloads,
  parseRecipients,
  validateForm,
  validatePolicy,
  type FormErrors,
  type LevelRules,
  type Message,
  type PublicLevel,
} from './form';

/** Public tenant description (GET /tenant). */
export type PublicTenant = components['schemas']['PublicTenant'];
/** Deposit session (POST /deposit-sessions 201, GET /deposit-sessions/current). */
export type DepositSession = components['schemas']['DepositSession'];
/** Verification challenge (POST /deposit-sessions 202). */
export type VerificationChallenge = components['schemas']['VerificationChallenge'];
/** Body of POST /transfers. */
export type TransferCreate = components['schemas']['TransferCreate'];
/** Scan status of a file. */
export type ScanStatus = components['schemas']['ScanStatus'];

/** Invitation the depositor arrived with (/i/:token, after the invitation landing). */
export interface InvitationContext {
  /** Invitation token (inv_...). */
  token: string;
  /** Invited address, used to request the code. */
  email: string;
  /** Internal user who issued the invitation (the recipient of the files). */
  invitedBy: string;
  /** Message of the inviter (plain text). */
  message?: string | undefined;
}

/** Reply the depositor is making (/d/:token/reply, after the reply session was opened). */
export interface ReplyContext {
  /** Download link token of the transfer replied to. */
  token: string;
  /** Sender of the original transfer, single recipient of the reply. */
  recipient: string;
  /** Expiry of the original transfer (the session never outlives it). */
  transferExpiresAt: string;
}

/** Step of the deposit page. */
export type Step =
  | 'loading'
  | 'error'
  | 'maintenance'
  | 'email'
  | 'code'
  | 'form'
  | 'resume'
  | 'upload'
  | 'finalizing'
  | 'done';

/** File-like value accepted by the flow (File in the browser). */
export interface DepositFile extends Blob {
  readonly name: string;
  readonly lastModified: number;
}

/** Values of the deposit form, bound by the form screen. */
export interface DepositForm {
  recipientsText: string;
  message: string;
  expiryDays: number | undefined;
  password: string;
  deleteAfterFirstDownload: boolean;
  /** Maximum number of downloads as typed; empty for no limit. */
  maxDownloadsText: string;
  /** Every recipient proves their address by code (a per-recipient link each). */
  recipientVerification: boolean;
  /** Key of the chosen confidentiality level; undefined when the tenant has none. */
  confidentialityLevel: string | undefined;
  files: DepositFile[];
}

/** Error displayed on the current step: a translated message or an API error to describe. */
export type StepError = { message: Message } | { cause: unknown };

/** Outcome of finalizeAndWait (injected). */
export type FinalizeFn = (transferId: string, options: FinalizeOptions) => Promise<FinalizeOutcome>;

/** Builds the upload engine of a transfer (injected). */
export type EngineFactory = (specs: UploadFileSpec[], cancelTransfer: () => Promise<void>) => UploadEngine;

/** Dependencies of the flow. */
export interface DepositFlowDeps {
  api: ApiClient;
  /** Translator (the shared i18n instance). */
  tr: Translator;
  /** Forgets the CSRF token when the session ends. */
  clearCsrf: () => void;
  resumeStore: ResumeStore;
  createEngine: EngineFactory;
  finalize: FinalizeFn;
  /** Polls a transfer already finalized until it is decided (reload during the analysis). */
  poll: FinalizeFn;
  /** Asks the user a yes/no question (window.confirm), before leaving during an upload. */
  confirm: (message: string) => boolean;
  /** Waits ms milliseconds (setTimeout by default), between the cancellation attempts. */
  sleep?: (ms: number) => Promise<void>;
  /** Live-region announcement. */
  announce: (message: string, politeness?: 'polite' | 'assertive') => void;
  /** Current UI language, sent as TransferCreate.language. */
  language: () => string;
  /** Idempotency-Key generator (crypto.randomUUID by default). */
  newKey?: () => string;
  /** Clock (Date.now by default), for rate-limit countdowns. */
  now?: () => number;
}

/** Text of an upload engine announcement (pure). */
export function announcementText(tr: Pick<Translator, 't'>, a: UploadAnnouncement): string {
  switch (a.kind) {
    case 'progress':
      return tr.t('upload.announce.progress', { percent: a.percent });
    case 'file-done':
      return tr.t('upload.announce.fileDone', { name: a.name });
    case 'paused':
      return tr.t(a.reason === 'user' ? 'upload.announce.pausedUser' : 'upload.announce.pausedFailures');
    case 'error':
      return tr.t('upload.announce.error');
    case 'completed':
      return tr.t('upload.announce.completed');
    case 'cancelled':
      return tr.t('upload.announce.cancelled');
  }
}

const FINALIZE_ERRORS = new Set(['checksum-mismatch', 'state-conflict', 'transfer-gone', 'network']);

/** Translation key of a finalization failure. */
export function finalizeErrorKey(code: string): string {
  return FINALIZE_ERRORS.has(code) ? `upload.finalize.error.${code}` : 'upload.finalize.error.other';
}

/** Translation key of a scan status, for the recap (a generic key for a status unknown here). */
export function scanStatusKey(tr: Pick<Translator, 'has'>, status: ScanStatus): string {
  const key = `deposit.scan.${status}`;
  return tr.has(key) ? key : 'deposit.scan.other';
}

/**
 * Time during which DELETE /transfers/{id} is retried while it answers 409: the server keeps the
 * lock of an upload whose connection it has not yet seen die until its read timeout.
 */
export const CANCEL_RETRY_BUDGET_MS = 90_000;

/** Scan statuses that deserve a warning in the recap. */
export function scanWarningKey(status: ScanStatus): string | undefined {
  switch (status) {
    case 'infected':
      return 'deposit.done.warning.infected';
    case 'not_scanned_too_large':
    case 'not_scanned_encrypted':
      return 'deposit.done.warning.notScanned';
    case 'scan_error':
      return 'deposit.done.warning.scanError';
    default:
      return undefined;
  }
}

function isProblem(err: unknown, code?: string): err is ApiProblem {
  return err instanceof ApiProblem && (code === undefined || err.code === code);
}

function emptyForm(expiryDays: readonly number[] = [], levels: readonly PublicLevel[] = []): DepositForm {
  const level = defaultLevel(levels);
  return {
    recipientsText: '',
    message: '',
    expiryDays: keepExpiry(undefined, effectiveExpiryDays(expiryDays, level?.rules)),
    password: '',
    deleteAfterFirstDownload: false,
    maxDownloadsText: '',
    recipientVerification: false,
    confidentialityLevel: level?.key,
    files: [],
  };
}

/** The deposit flow of one page. Fields are reactive ($state) when read in components. */
export class DepositFlow {
  step = $state<Step>('loading');
  /** An action is in progress (buttons show a loading state). */
  busy = $state(false);
  session = $state.raw<DepositSession | undefined>(undefined);
  challenge = $state.raw<VerificationChallenge | undefined>(undefined);
  /** Email field of the email step. */
  email = $state('');
  /** Code field of the code step. */
  code = $state('');
  /** Error of the current step (general message). */
  stepError = $state.raw<StepError | undefined>(undefined);
  /** Field error of the email or code field. */
  fieldError = $state.raw<Message | undefined>(undefined);
  /** Information message (code resent, session ended...). */
  notice = $state.raw<Message | undefined>(undefined);
  /** Remaining code attempts after a wrong code. */
  attemptsRemaining = $state<number | undefined>(undefined);
  /** Clock time before which a new attempt is refused (rate limited). */
  retryAt = $state<number | undefined>(undefined);
  /** Maintenance message (plain text), when the tenant has one. */
  maintenanceMessage = $state<string | undefined>(undefined);
  /**
   * Language the maintenance message is written in (lang attribute, RGAA 8.7); undefined when
   * unknown or without message. It may differ from the UI language (server fallback).
   */
  maintenanceMessageLanguage = $state<string | undefined>(undefined);
  /** The invitation can no longer be used. */
  invitationGone = $state(false);
  /** Reply mode: the reply session is gone (expired, ended or never opened). */
  replyEnded = $state(false);
  /** Deposit form values. */
  form = $state<DepositForm>(emptyForm());
  /** Field errors of the form. */
  formErrors = $state.raw<FormErrors>({});
  /** Incremented each time the form is refused, so that the screen focuses the summary. */
  formRefusals = $state(0);
  /** Transfer being uploaded, scanned or recapped. */
  transfer = $state.raw<SenderTransfer | undefined>(undefined);
  /** Upload progress. */
  upload = $state.raw<UploadSnapshot | undefined>(undefined);
  /** Finalization failure message. */
  finalizeError = $state.raw<Message | undefined>(undefined);
  /** The finalization can be tried again. */
  finalizeRetryable = $state(false);
  /** Files refused by the blocklist at finalization. */
  blockedFiles = $state.raw<string[] | undefined>(undefined);
  /** Final state of the transfer on the done step. */
  outcome = $state<'available' | 'rejected' | undefined>(undefined);
  /** Interrupted upload found after a reload. */
  resumeRecord = $state.raw<ResumeRecord | undefined>(undefined);
  /** Files reselected on the resume step. */
  resumeFiles = $state.raw<DepositFile[]>([]);

  readonly tenant: PublicTenant;
  readonly invitation: InvitationContext | undefined;
  readonly reply: ReplyContext | undefined;
  readonly #deps: DepositFlowDeps;
  readonly #key: IdempotencyKey;
  readonly #now: () => number;
  readonly #sleep: (ms: number) => Promise<void>;
  /** Serialized body of the last createTransfer attempt sent with the current key. */
  #lastBody: string | undefined;
  #engine: UploadEngine | undefined;
  #unsubscribe: (() => void)[] = [];
  #contents: (Blob | undefined)[] = [];
  #finalizeAbort: AbortController | undefined;
  #disposed = false;

  constructor(
    tenant: PublicTenant,
    invitation: InvitationContext | undefined,
    deps: DepositFlowDeps,
    reply?: ReplyContext,
  ) {
    this.tenant = tenant;
    this.reply = reply;
    this.form.confidentialityLevel = defaultLevel(this.levels)?.key;
    this.#syncLevel();
    this.invitation = invitation;
    this.#deps = deps;
    this.#key = new IdempotencyKey(deps.newKey);
    this.#now = deps.now ?? Date.now;
    this.#sleep = deps.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    if (invitation !== undefined) {
      this.email = invitation.email;
    }
  }

  // ---- Derived values ---------------------------------------------------------------------

  /** The depositor is an invited external user: no recipients to choose. */
  get isExternal(): boolean {
    return this.session?.kind === 'external' || (this.session === undefined && this.invitation !== undefined);
  }

  /** The depositor is replying to a transfer: the only recipient is its sender. */
  get isReply(): boolean {
    return this.session?.kind === 'reply' || this.reply !== undefined;
  }

  /** Recipient of a reply (sender of the original transfer). */
  get replyRecipient(): string | undefined {
    return this.session?.reply?.recipient ?? this.reply?.recipient;
  }

  /** Recipient of the files of an external depositor. */
  get invitedBy(): string | undefined {
    return this.session?.invitation?.invitedBy ?? this.invitation?.invitedBy;
  }

  /** The session may issue invitations (internal depositor). */
  get canInvite(): boolean {
    return this.session?.kind === 'internal' && this.session.canInvite;
  }

  /** The tenant lets verified internal addresses deposit from outside (a code at each deposit). */
  get remoteDepositAllowed(): boolean {
    return this.tenant.features?.remoteInternalDeposit === true;
  }

  /** The session is an internal address depositing from outside the network. */
  get isRemoteSession(): boolean {
    return this.session?.kind === 'internal_remote';
  }

  /** Confidentiality levels the sender can use, in display order (see selectableLevels). */
  get levels(): readonly PublicLevel[] {
    return selectableLevels(
      this.tenant.confidentialityLevels ?? [],
      this.limits.expiryDays,
      this.tenant.features?.recipientVerification === true,
    );
  }

  /** The tenant has levels but none can be used: no transfer can be sent. */
  get noUsableLevel(): boolean {
    return (this.tenant.confidentialityLevels ?? []).length > 0 && this.levels.length === 0;
  }

  /** The chosen confidentiality level, undefined when the tenant has none. */
  get level(): PublicLevel | undefined {
    return levelByKey(this.levels, this.form.confidentialityLevel) ?? defaultLevel(this.levels);
  }

  /** Rules of the chosen level; they apply even when the selector is hidden. */
  get rules(): LevelRules | undefined {
    return this.level?.rules;
  }

  /** The "maximum number of downloads" option is offered to senders. */
  get maxDownloadsOffered(): boolean {
    return this.tenant.features?.maxDownloads === true;
  }

  /** The "recipients must verify their address" option is offered to senders. */
  get recipientVerificationOffered(): boolean {
    return this.tenant.features?.recipientVerification === true;
  }

  /** Recipient verification as sent: forced by the level or chosen by the sender. */
  get recipientVerificationEffective(): boolean {
    return effectiveRecipientVerification(
      this.form.recipientVerification,
      this.rules,
      this.recipientVerificationOffered,
    );
  }

  /** Durations offered: those of the limits that the chosen level allows. */
  get expiryOptions(): number[] {
    return effectiveExpiryDays(this.limits.expiryDays, this.rules);
  }

  /** Delete-after-first-download as sent: forced by the level or chosen by the sender. */
  get deleteAfterFirstEffective(): boolean {
    return effectiveDeleteAfterFirst(this.form.deleteAfterFirstDownload, this.rules);
  }

  /** Chooses a confidentiality level; the duration and the download limit stay valid. */
  setLevel(key: string): void {
    this.form.confidentialityLevel = key;
    this.#syncLevel();
  }

  #syncLevel(): void {
    this.form.expiryDays = keepExpiry(this.form.expiryDays, this.expiryOptions);
    this.form.maxDownloadsText = keepMaxDownloads(this.form.maxDownloadsText, this.rules);
  }

  /** Limits of the session (or of the tenant before identification). */
  get limits(): { maxTransferBytes: number; expiryDays: number[] } {
    return this.session?.limits ?? this.tenant.limits;
  }

  /** Total size of the selected files. */
  get totalBytes(): number {
    return this.form.files.reduce((sum, f) => sum + f.size, 0);
  }

  /** Addresses parsed from the recipients field. */
  get recipients(): string[] {
    return parseRecipients(this.form.recipientsText);
  }

  /** Text of the current step error. */
  get errorText(): string | undefined {
    const e = this.stepError;
    if (e === undefined) return undefined;
    return 'message' in e
      ? this.#deps.tr.t(e.message.key, e.message.params)
      : problemMessage(this.#deps.tr, e.cause);
  }

  /** Seconds before a new attempt is allowed (0 when not rate limited). */
  secondsBeforeRetry(now: number = this.#now()): number {
    return this.retryAt === undefined ? 0 : Math.max(0, Math.ceil((this.retryAt - now) / 1000));
  }

  /** Fingerprints of the interrupted transfer still missing a reselected file. */
  get resumeMissing(): FileFingerprint[] {
    const record = this.resumeRecord;
    const transfer = this.transfer;
    if (record === undefined || transfer === undefined) return [];
    const match = matchFiles(record, this.resumeFiles);
    return record.files.filter((fp, i) => {
      const file = transfer.files[i];
      const complete = file !== undefined && (file.uploadOffset ?? 0) >= file.size;
      return match.files[i] === undefined && !complete;
    });
  }

  /** True while bytes may still be sent (beforeunload warning). */
  isUploading(): boolean {
    return this.#engine?.isActive() === true;
  }

  /**
   * Guard of an in-app navigation: asks for a confirmation while an upload is running.
   * Returns true when the page may be left (the upload is then stopped by dispose()).
   */
  confirmLeave(): boolean {
    return !this.isUploading() || this.#deps.confirm(this.#deps.tr.t('deposit.upload.leaveConfirm'));
  }

  // ---- Bootstrap and identification -----------------------------------------------------

  /** Starts the flow: maintenance check, current session, interrupted upload. */
  async start(): Promise<void> {
    this.#reset();
    this.step = 'loading';
    if (this.tenant.maintenance) {
      this.#maintenance(this.tenant.maintenanceMessage, this.tenant.maintenanceMessageLanguage);
      return;
    }
    let session: DepositSession | undefined;
    try {
      session = (await this.#deps.api.get('/deposit-sessions/current')).data;
    } catch (err) {
      if (!isProblem(err) || err.status !== 401) {
        this.stepError = { cause: err };
        this.step = 'error';
        return;
      }
    }
    if (this.reply !== undefined) {
      // Reply mode: only a reply session fits, else the reply must be started again.
      if (session !== undefined && session.kind === 'reply') {
        await this.#afterSession(session);
      } else {
        this.replyEnded = true;
      }
      return;
    }
    if (session !== undefined && this.#sessionFits(session)) {
      await this.#afterSession(session);
      return;
    }
    if (this.invitation !== undefined) {
      // The depositor clicked "Continue" on the invitation landing: send the code at once.
      this.step = 'email';
      await this.submitEmail();
      return;
    }
    this.step = 'email';
  }

  /** Requests a code (or a session for a recognised internal address). */
  async submitEmail(): Promise<void> {
    if (this.busy || this.invitationGone) return;
    const email = this.email.trim();
    this.notice = undefined;
    if (!isEmail(email)) {
      this.fieldError = { key: email === '' ? 'fieldErrors.required' : 'fieldErrors.invalid-email' };
      return;
    }
    this.fieldError = undefined;
    this.stepError = undefined;
    this.busy = true;
    try {
      const body =
        this.invitation === undefined ? { email } : { email, invitationToken: this.invitation.token };
      const res = await this.#deps.api.post('/deposit-sessions', { body });
      this.retryAt = undefined;
      if (res.status === 201) {
        await this.#afterSession(res.data as DepositSession);
      } else {
        this.challenge = res.data as VerificationChallenge;
        this.attemptsRemaining = undefined;
        this.code = '';
        this.step = 'code';
      }
    } catch (err) {
      this.#identificationError(err);
    } finally {
      this.busy = false;
    }
  }

  /** Sends the code typed by the depositor. */
  async submitCode(): Promise<void> {
    const challenge = this.challenge;
    if (this.busy || challenge === undefined) return;
    const code = this.code.replace(/\s+/g, '');
    this.notice = undefined;
    if (!/^\d{6}$/.test(code)) {
      this.fieldError = { key: code === '' ? 'fieldErrors.required' : 'deposit.code.format' };
      return;
    }
    this.fieldError = undefined;
    this.stepError = undefined;
    this.busy = true;
    try {
      const res = await this.#deps.api.post('/verification-challenges/{challengeId}/confirm', {
        path: { challengeId: challenge.challengeId },
        body: { code },
      });
      this.challenge = undefined;
      await this.#afterSession(res.data);
    } catch (err) {
      if (isProblem(err, 'verification-code-invalid')) {
        this.attemptsRemaining = err.attemptsRemaining;
        this.fieldError = { key: 'deposit.code.wrong' };
        this.code = '';
      } else if (isProblem(err, 'verification-exhausted') || isProblem(err, 'not-found')) {
        this.challenge = undefined;
        this.step = 'email';
        this.notice = undefined;
        this.stepError = { message: { key: 'deposit.code.exhausted' } };
      } else {
        this.#identificationError(err);
      }
    } finally {
      this.busy = false;
    }
  }

  /** Requests a new code for the same address. */
  async resendCode(): Promise<void> {
    if (this.busy) return;
    await this.submitEmail();
    if (this.step === 'code' && this.stepError === undefined && this.fieldError === undefined) {
      this.notice = { key: 'deposit.code.resent' };
    }
  }

  /** Goes back to the email step (another address). */
  changeEmail(): void {
    this.challenge = undefined;
    this.code = '';
    this.fieldError = undefined;
    this.stepError = undefined;
    this.notice = undefined;
    this.attemptsRemaining = undefined;
    this.step = 'email';
  }

  // ---- Form -------------------------------------------------------------------------------

  /** Adds chosen or dropped files (duplicates skipped). */
  addFiles(files: readonly DepositFile[]): void {
    this.form.files = addFiles(this.form.files, files);
    this.#clearFileErrors();
  }

  /** Removes the file at index. */
  removeFile(index: number): void {
    this.form.files = this.form.files.filter((_f, i) => i !== index);
    this.#clearFileErrors();
  }

  /** Validates and creates the transfer, then starts the upload. */
  async submitTransfer(): Promise<void> {
    const session = this.session;
    if (this.busy || session === undefined) return;
    const needRecipients = session.kind !== 'external' && session.kind !== 'reply';
    const errors = {
      ...validateForm(this.form, { ...session.limits, expiryDays: this.expiryOptions }, needRecipients),
      ...validatePolicy(this.form.password, this.form.maxDownloadsText, this.rules, this.maxDownloadsOffered),
    };
    this.stepError = undefined;
    this.notice = undefined;
    if (Object.keys(errors).length > 0) {
      this.formErrors = errors;
      this.formRefusals++;
      return;
    }
    this.formErrors = {};
    const files = [...this.form.files];
    const body: TransferCreate = {
      expiryDays: this.form.expiryDays as TransferCreate['expiryDays'],
      deleteAfterFirstDownload: this.deleteAfterFirstEffective,
      files: files.map((f) =>
        f.type === '' ? { name: f.name, size: f.size } : { name: f.name, size: f.size, mediaType: f.type },
      ),
    };
    if (needRecipients) body.recipients = parseRecipients(this.form.recipientsText);
    if (this.form.message.trim() !== '') body.message = this.form.message;
    if (this.form.password !== '') body.password = this.form.password;
    if (this.maxDownloadsOffered) {
      const parsed = parseMaxDownloads(this.form.maxDownloadsText);
      if (parsed.ok && parsed.value !== undefined) body.maxDownloads = parsed.value;
    }
    if (this.recipientVerificationEffective) body.recipientVerification = true;
    if (this.level !== undefined) body.confidentialityLevel = this.level.key;
    const language = this.#deps.language();
    if ((languageValues as readonly string[]).includes(language)) {
      body.language = language as TransferCreate['language'];
    }
    // The key is kept across transient failures only while the request stays the same.
    const serialized = JSON.stringify(body);
    if (this.#lastBody !== undefined && this.#lastBody !== serialized) this.#key.renew();
    this.#lastBody = serialized;
    this.busy = true;
    let transfer: SenderTransfer;
    try {
      transfer = (
        await this.#deps.api.post('/transfers', { body, headers: { 'Idempotency-Key': this.#key.value } })
      ).data;
    } catch (err) {
      this.busy = false;
      this.#transferError(err);
      return;
    }
    this.busy = false;
    this.#renewKey();
    this.retryAt = undefined;
    this.#deps.resumeStore.save({ transferId: transfer.id, files: files.map((f) => fingerprint(f)) });
    this.form.password = '';
    this.#runUpload(transfer, files, true);
  }

  // ---- Upload -----------------------------------------------------------------------------

  /** Pauses the upload. */
  pause(): void {
    this.#engine?.pause();
  }

  /** Resumes the upload (or retries at once while waiting). */
  resume(): void {
    this.#engine?.resume();
  }

  /**
   * Cancels the upload and abandons the transfer; back to the form. The cancellation is retried
   * while the server still holds the upload lock (409), then reported if it still fails.
   */
  async cancelUpload(): Promise<void> {
    const engine = this.#engine;
    if (engine === undefined || this.busy) return;
    this.busy = true;
    this.notice = { key: 'deposit.upload.cancelling' };
    let failed = false;
    try {
      await engine.cancel();
    } catch {
      // The transfer expires on the server anyway (TT_UPLOAD_TTL): the user is told.
      failed = true;
    } finally {
      this.busy = false;
    }
    if (this.#disposed || this.#engine !== engine) return;
    this.#deps.resumeStore.clear();
    this.#disposeEngine();
    this.transfer = undefined;
    this.upload = undefined;
    this.notice = failed ? undefined : { key: 'deposit.upload.cancelled' };
    this.stepError = failed ? { message: { key: 'deposit.upload.cancelFailed' } } : undefined;
    this.step = 'form';
  }

  /** Tries the finalization again after a transient failure. */
  async retryFinalize(): Promise<void> {
    if (this.transfer !== undefined) {
      await this.#finalize(this.transfer.id);
    }
  }

  // ---- Resume after a reload ----------------------------------------------------------------

  /** Adds reselected files on the resume step. */
  addResumeFiles(files: readonly DepositFile[]): void {
    this.resumeFiles = addFiles(this.resumeFiles, files);
  }

  /** Continues the interrupted upload with the reselected files. */
  continueResume(): void {
    const record = this.resumeRecord;
    const transfer = this.transfer;
    if (record === undefined || transfer === undefined || this.resumeMissing.length > 0) return;
    const match = matchFiles(record, this.resumeFiles);
    this.resumeRecord = undefined;
    this.resumeFiles = [];
    this.#runUpload(transfer, match.files, false);
  }

  /** Abandons the interrupted upload and shows an empty form. */
  async discardResume(): Promise<void> {
    const transfer = this.transfer;
    this.#deps.resumeStore.clear();
    this.resumeRecord = undefined;
    this.resumeFiles = [];
    this.transfer = undefined;
    this.step = 'form';
    // The previous page may have left an upload whose lock the server still holds.
    if (transfer !== undefined && !(await this.#cancelOnServer(transfer.id, true)) && this.step === 'form') {
      this.stepError = { message: { key: 'deposit.upload.cancelFailed' } };
    }
  }

  // ---- Done -------------------------------------------------------------------------------

  /** Starts a new transfer with the same session. */
  newTransfer(): void {
    this.#abortFinalize();
    this.#disposeEngine();
    this.#deps.resumeStore.clear();
    this.transfer = undefined;
    this.upload = undefined;
    this.outcome = undefined;
    this.blockedFiles = undefined;
    this.finalizeError = undefined;
    this.stepError = undefined;
    this.notice = undefined;
    this.formErrors = {};
    this.form = emptyForm(this.limits.expiryDays, this.levels);
    this.#renewKey();
    this.step = this.session === undefined ? 'email' : 'form';
  }

  /**
   * Gives up a transfer that cannot complete (fatal upload error, refused finalization):
   * abandons it on the server while it is still uploading, then shows an empty form.
   */
  async abandonTransfer(): Promise<void> {
    const transfer = this.transfer;
    this.newTransfer();
    if (transfer !== undefined && transfer.status === 'uploading') {
      await this.#cancelOnServer(transfer.id);
    }
  }

  /** Ends the deposit session (DELETE /deposit-sessions/current). */
  async endSession(): Promise<void> {
    if (this.busy) return;
    this.busy = true;
    try {
      await this.#deps.api.delete('/deposit-sessions/current');
    } catch {
      // Already expired or revoked: the local state is cleared anyway.
    } finally {
      this.busy = false;
    }
    this.#deps.clearCsrf();
    this.newTransfer();
    this.session = undefined;
    this.step = 'email';
    this.notice = { key: 'deposit.session.ended' };
    if (this.reply !== undefined) this.replyEnded = true;
  }

  /** Stops background work (page left). */
  dispose(): void {
    this.#disposed = true;
    this.#abortFinalize();
    this.#disposeEngine();
  }

  // ---- Internals --------------------------------------------------------------------------

  #reset(): void {
    this.stepError = undefined;
    this.fieldError = undefined;
    this.notice = undefined;
    this.retryAt = undefined;
  }

  /** In invitation mode, an existing session is reused only if it is for this invitation. */
  #sessionFits(session: DepositSession): boolean {
    if (this.invitation === undefined) return true;
    return (
      session.kind === 'external' &&
      session.email.toLowerCase() === this.invitation.email.toLowerCase() &&
      session.invitation?.invitedBy.toLowerCase() === this.invitation.invitedBy.toLowerCase()
    );
  }

  #maintenance(message: string | undefined, language: string | undefined): void {
    this.maintenanceMessage = message === undefined || message === '' ? undefined : message;
    this.maintenanceMessageLanguage = this.maintenanceMessage === undefined ? undefined : language;
    this.step = 'maintenance';
  }

  /**
   * Switches to maintenance on a 503 maintenance problem. The problem detail does not say which
   * language the message is written in: it is taken from the tenant description when that one
   * holds the same message, else from a fresh GET /tenant (same negotiation as the problem).
   */
  #maintenanceProblem(detail: string | undefined): void {
    const known = detail !== undefined && detail === this.tenant.maintenanceMessage;
    this.#maintenance(detail, known ? this.tenant.maintenanceMessageLanguage : undefined);
    if (this.maintenanceMessage !== undefined && this.maintenanceMessageLanguage === undefined) {
      void this.#refreshMaintenanceLanguage(this.maintenanceMessage);
    }
  }

  /** Reads the language of the maintenance message from GET /tenant; failures are ignored. */
  async #refreshMaintenanceLanguage(message: string): Promise<void> {
    let fresh: PublicTenant | undefined;
    try {
      fresh = (await this.#deps.api.get('/tenant')).data;
    } catch {
      return;
    }
    if (
      fresh?.maintenanceMessage === message &&
      this.step === 'maintenance' &&
      this.maintenanceMessage === message
    ) {
      this.maintenanceMessageLanguage = fresh.maintenanceMessageLanguage;
    }
  }

  async #afterSession(session: DepositSession): Promise<void> {
    this.session = session;
    this.fieldError = undefined;
    this.stepError = undefined;
    this.attemptsRemaining = undefined;
    this.retryAt = undefined;
    this.form.confidentialityLevel = this.level?.key;
    this.#syncLevel();
    const record = this.#deps.resumeStore.load();
    if (record !== undefined) {
      try {
        const transfer = (
          await this.#deps.api.get('/transfers/{transferId}', { path: { transferId: record.transferId } })
        ).data;
        if (transfer.status === 'uploading' && transfer.files.length === record.files.length) {
          this.transfer = transfer;
          this.resumeRecord = record;
          this.resumeFiles = [];
          this.step = 'resume';
          return;
        }
        if (transfer.status === 'scanning') {
          // Reloaded during the antivirus analysis: wait for the decision, do not finalize again.
          this.transfer = transfer;
          void this.#finalize(transfer.id, true);
          return;
        }
        if (transfer.status === 'available' || transfer.status === 'rejected') {
          this.#deps.resumeStore.clear();
          this.transfer = transfer;
          this.outcome = transfer.status;
          this.step = 'done';
          return;
        }
        this.#deps.resumeStore.clear();
      } catch (err) {
        if (!(err instanceof NetworkError)) {
          this.#deps.resumeStore.clear();
        }
      }
    }
    this.step = 'form';
  }

  /** Handles the errors common to every request. Returns true when handled. */
  #commonError(err: unknown): boolean {
    if (isProblem(err, 'maintenance')) {
      this.#maintenanceProblem(err.problem?.detail);
      return true;
    }
    if (isProblem(err, 'rate-limited')) {
      this.retryAt = this.#now() + (err.retryAfterSeconds ?? 60) * 1000;
      this.stepError = { cause: err };
      return true;
    }
    if (isProblem(err, 'unauthenticated') && this.step !== 'email' && this.step !== 'code') {
      this.#sessionExpired();
      return true;
    }
    return false;
  }

  #sessionExpired(): void {
    this.#abortFinalize();
    this.#disposeEngine();
    this.session = undefined;
    this.#deps.clearCsrf();
    this.challenge = undefined;
    this.step = 'email';
    this.stepError = undefined;
    this.notice = { key: 'deposit.session.expired' };
    if (this.reply !== undefined) this.replyEnded = true;
  }

  #identificationError(err: unknown): void {
    if (this.#commonError(err)) return;
    if (isProblem(err, 'deposit-not-allowed')) {
      this.stepError = { message: { key: 'deposit.email.notAllowed' } };
    } else if (isProblem(err, 'invitation-gone')) {
      this.invitationGone = true;
      this.challenge = undefined;
      this.step = 'email';
      this.stepError = { message: { key: 'deposit.email.invitationGone' } };
    } else if (isProblem(err, 'validation-failed')) {
      this.fieldError = { key: 'fieldErrors.invalid-email' };
    } else {
      this.stepError = { cause: err };
    }
  }

  #transferError(err: unknown): void {
    const transient =
      err instanceof NetworkError || (err instanceof ApiProblem && (err.status >= 500 || err.status === 429));
    if (!transient) {
      // The next submission is a new request (its body may differ): new Idempotency-Key.
      this.#renewKey();
    }
    if (this.#commonError(err)) return;
    if (isProblem(err, 'validation-failed')) {
      this.formErrors = mapServerErrors(err.errors, (key) => this.#deps.tr.has(key));
      this.formRefusals++;
    } else if (isProblem(err, 'confidentiality-rule-violated')) {
      this.#ruleErrors(err, mapRuleErrors(err.errors));
    } else if (isProblem(err, 'recipient-domain-refused')) {
      this.#ruleErrors(err, mapRecipientDomainErrors(err.errors));
    } else if (isProblem(err, 'transfer-too-large')) {
      this.formErrors = { files: { key: 'deposit.form.files.tooLarge' } };
      this.formRefusals++;
    } else if (isProblem(err, 'abuse-threshold-blocked')) {
      this.stepError = { message: { key: 'deposit.form.abuseBlocked' } };
    } else if (isProblem(err, 'deposit-not-allowed')) {
      this.stepError = { message: { key: 'deposit.email.notAllowed' } };
    } else {
      this.stepError = { cause: err };
    }
  }

  /** Shows rule errors next to their fields; the general message when none matches a field. */
  #ruleErrors(err: ApiProblem, mapped: FormErrors): void {
    if (invalidFields(mapped).length === 0) {
      this.stepError = { cause: err };
      return;
    }
    this.formErrors = mapped;
    this.formRefusals++;
  }

  #clearFileErrors(): void {
    const errors = this.formErrors;
    if (Object.keys(errors).some((k) => k === 'files' || k.startsWith('files.'))) {
      this.formErrors = Object.fromEntries(
        Object.entries(errors).filter(([k]) => k !== 'files' && !k.startsWith('files.')),
      );
    }
  }

  /** Starts a new submission: new Idempotency-Key, no previous body. */
  #renewKey(): void {
    this.#key.renew();
    this.#lastBody = undefined;
  }

  /**
   * Uploads the files of transfer. fresh: transfer is the createTransfer answer (exact offsets);
   * otherwise the engine asks the server for the offsets first.
   */
  #runUpload(transfer: SenderTransfer, contents: readonly (Blob | undefined)[], fresh: boolean): void {
    this.#disposeEngine();
    this.transfer = transfer;
    this.#contents = [...contents];
    this.finalizeError = undefined;
    this.blockedFiles = undefined;
    const engine = this.#deps.createEngine(uploadSpecs(transfer, contents, fresh), async () => {
      if (!(await this.#cancelOnServer(transfer.id, true))) {
        throw new Error('transfer not cancelled');
      }
    });
    this.#engine = engine;
    this.#unsubscribe.push(
      engine.subscribe((snapshot) => {
        this.upload = snapshot;
      }),
      engine.onAnnounce((a) => {
        this.#deps.announce(announcementText(this.#deps.tr, a), a.kind === 'error' ? 'assertive' : 'polite');
      }),
    );
    this.step = 'upload';
    engine.start().then(
      (result) => {
        if (this.#engine === engine && result === 'completed') {
          void this.#finalize(transfer.id);
        }
      },
      (err: unknown) => {
        if (this.#engine !== engine) return;
        if (err instanceof UploadError && err.code === 'unauthenticated') {
          this.#sessionExpired();
        }
        // Other fatal errors stay on the upload step (snapshot.error).
      },
    );
  }

  /** Finalizes the transfer then waits for the decision (pollOnly: already finalized). */
  async #finalize(transferId: string, pollOnly = false): Promise<void> {
    this.#abortFinalize();
    const controller = new AbortController();
    this.#finalizeAbort = controller;
    this.step = 'finalizing';
    this.finalizeError = undefined;
    this.finalizeRetryable = false;
    this.blockedFiles = undefined;
    const outcome = await (pollOnly ? this.#deps.poll : this.#deps.finalize)(transferId, {
      signal: controller.signal,
      onUpdate: (t) => {
        if (!controller.signal.aborted) this.transfer = t;
      },
    });
    if (controller.signal.aborted || this.#disposed) return;
    this.#finalizeAbort = undefined;
    switch (outcome.kind) {
      case 'available':
      case 'rejected':
        this.transfer = outcome.transfer;
        this.outcome = outcome.kind;
        this.#deps.resumeStore.clear();
        this.#disposeEngine();
        this.step = 'done';
        this.#deps.announce(
          this.#deps.tr.t(
            outcome.kind === 'available' ? 'upload.finalize.available' : 'upload.finalize.rejected',
          ),
        );
        return;
      case 'upload-incomplete':
        await this.#resumeIncomplete(transferId);
        return;
      case 'blocked':
        this.blockedFiles = outcome.files;
        this.#deps.resumeStore.clear();
        this.#deps.announce(this.#deps.tr.t('upload.finalize.blocked'), 'assertive');
        await this.#cancelOnServer(transferId);
        return;
      case 'failed':
        if (outcome.code === 'unauthenticated') {
          this.#sessionExpired();
          return;
        }
        if (outcome.code === 'maintenance') {
          this.finalizeRetryable = true;
          this.finalizeError = { key: 'errors.maintenance' };
          return;
        }
        this.finalizeRetryable =
          outcome.code === 'network' || (outcome.status ?? 0) >= 500 || outcome.status === 429;
        this.finalizeError = { key: finalizeErrorKey(outcome.code) };
        if (!this.finalizeRetryable) this.#deps.resumeStore.clear();
        this.#deps.announce(this.#deps.tr.t(this.finalizeError.key), 'assertive');
        return;
      case 'stopped':
        return;
    }
  }

  async #resumeIncomplete(transferId: string): Promise<void> {
    this.notice = { key: 'upload.finalize.incomplete' };
    try {
      const transfer = (await this.#deps.api.get('/transfers/{transferId}', { path: { transferId } })).data;
      this.#runUpload(transfer, this.#contents, false);
    } catch (err) {
      if (isProblem(err, 'unauthenticated')) {
        this.#sessionExpired();
        return;
      }
      this.finalizeRetryable = err instanceof NetworkError;
      this.finalizeError = { key: finalizeErrorKey(err instanceof NetworkError ? 'network' : 'other') };
    }
  }

  /**
   * Abandons a transfer on the server. Returns false when it could not be abandoned; a transfer
   * already gone counts as abandoned. retryConflicts: retries a 409 (the server still holds the
   * upload lock of a request it has not yet seen die) after 1, 2, 4, 8, 10... s for up to
   * CANCEL_RETRY_BUDGET_MS.
   */
  async #cancelOnServer(transferId: string, retryConflicts = false): Promise<boolean> {
    let waited = 0;
    for (let attempt = 1; ; attempt++) {
      try {
        await this.#deps.api.delete('/transfers/{transferId}', { path: { transferId } });
        return true;
      } catch (err) {
        if (isProblem(err) && (err.status === 404 || err.status === 410)) return true;
        const conflict = isProblem(err) && err.status === 409;
        if (!retryConflicts || !conflict || waited >= CANCEL_RETRY_BUDGET_MS || this.#disposed) {
          return false;
        }
        const delay = conflictDelay(attempt);
        waited += delay;
        await this.#sleep(delay);
      }
    }
  }

  #abortFinalize(): void {
    this.#finalizeAbort?.abort();
    this.#finalizeAbort = undefined;
  }

  /** Stops the current engine (no DELETE) and forgets it. */
  #disposeEngine(): void {
    for (const off of this.#unsubscribe) off();
    this.#unsubscribe = [];
    this.#engine?.stop();
    this.#engine = undefined;
  }
}
