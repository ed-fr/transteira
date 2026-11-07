// State machine of the public deposit page (CLAUDE.md sections 7, 8, 9; step 15 design,
// "Public screens" item 1). The screens (*.svelte in this folder) only render the state and call
// the actions below; every browser dependency is injected so that the flow is unit tested in
// Node with a fake API (fetch) and a fake upload engine.
//
// Steps:
//   loading → (maintenance | email | form | resume | error)
//   email → code (202) | form (201)          code → form | email (code exhausted)
//   form → upload → finalizing → done        upload → form (cancelled)
//   form → preparing (end-to-end encryption: hash pass) → form (transfer created) → upload;
//          preparing → form (cancelled)
//   resume (reload during an upload) → upload | form
//   reload during the antivirus analysis → finalizing (polling only) → done; reload once the
//   transfer is decided → done
// The download link of a transfer is never shown to the depositor (design decision D2): the
// done step is a recap only.
//
// End-to-end encryption (V2, docs/architecture/e2e-format.md): the browser draws the transfer key
// K, hashes every plaintext file (phase "preparing"), seals the metadata and the message, then
// declares the generic names and the ciphertext sizes. The upload engine reads each tus chunk from
// the encryption Worker (deterministic once the salt of a file is drawn), so that any resume,
// after a reload too (K and the salts are in the resume record), regenerates the same bytes. K is
// shown once on the done step and then forgotten.
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
import { fullName, withPath, type AcceptedFile } from '../../shared/components/folders';
import { decodeBase64Url, encodeBase64Url } from '../../shared/e2e/base64url';
import { sealMessage, sealMetadata } from '../../shared/e2e/sealed';
import {
  DEFAULT_CHUNK_SIZE,
  SALT_SIZE,
  ciphertextSize,
  e2eFileName,
  encodeKey,
  generateTransferKey,
  importTransferKey,
  parseKey,
  randomBytes,
} from '../../shared/e2e/tte2';
import { isAbortError, isFileChangedError } from '../../shared/e2e/upload-crypto-core';
import { openUploadCrypto, type UploadCrypto } from '../../shared/e2e/upload-crypto';
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
  MAX_FILES,
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
/** End-to-end encryption policy (tenant or level). */
export type E2ePolicy = components['schemas']['E2ePolicy'];

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

/** Drop link the depositor arrived with (/drop/:token, after the drop link landing). */
export interface DropLinkContext {
  /** Drop link token (ttd_...). */
  token: string;
  /** Label of the link, shown to the depositor ("Files will be sent to: label"). */
  label: string;
  /** Validity of the deposits, imposed by the link. */
  validityDays: number;
  /** Key of the confidentiality level imposed by the link; undefined for the tenant default. */
  levelKey?: string | undefined;
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
  | 'preparing'
  | 'resume'
  | 'upload'
  | 'finalizing'
  | 'done';

/** File-like value accepted by the flow (File in the browser). */
export interface DepositFile extends Blob {
  readonly name: string;
  readonly lastModified: number;
  /** Relative folder inside the transfer, absent for the root (set from a picked folder). */
  path?: string | undefined;
  /** The file or one of its folders starts with a dot (flagged in the list). */
  hidden?: boolean | undefined;
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
  /** Link-only transfer: no mail to the recipients, the sender passes the link on (since 2.0). */
  linkOnly: boolean;
  /** End-to-end encryption chosen by the sender (since 2.0); imposed when the policy requires it. */
  endToEnd: boolean;
  /** Key of the chosen confidentiality level; undefined when the tenant has none. */
  confidentialityLevel: string | undefined;
  files: DepositFile[];
}

/** Error displayed on the current step: a translated message or an API error to describe. */
export type StepError = { message: Message } | { cause: unknown };

/** Outcome of finalizeAndWait (injected). */
export type FinalizeFn = (transferId: string, options: FinalizeOptions) => Promise<FinalizeOutcome>;

/** Progress of the hash pass of an end-to-end encrypted transfer. */
export interface Preparation {
  /** create: before the transfer is created; resume: check of the files reselected after a reload. */
  kind: 'create' | 'resume';
  hashedBytes: number;
  totalBytes: number;
  /** Integer percentage (100 for empty files). */
  percent: number;
}

/** Plaintext description of a file of an end-to-end encrypted transfer, known to the browser only. */
export interface E2EFileInfo {
  name: string;
  /** Relative folder, '' for the root. */
  path: string;
  /** SHA-256 of the plaintext (computed by this page, or kept by the resume record). */
  sha256?: string | undefined;
}

/** Opens the encryption service of a transfer (injected; openUploadCrypto by default). */
export type CryptoFactory = (key: CryptoKey) => Promise<UploadCrypto>;

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
  /** Encryption service of an end-to-end encrypted transfer (Worker, else in the page). */
  openCrypto?: CryptoFactory;
}

/** Encryption state of the end-to-end encrypted transfer being prepared or uploaded. */
interface E2EState {
  key: Uint8Array<ArrayBuffer>;
  /** Header salt of each file, in the declared order. */
  salts: Uint8Array<ArrayBuffer>[];
  chunkSize: number;
  /** Opened on first use, released with the state. */
  crypto?: Promise<UploadCrypto> | undefined;
  /** Set once the state is released: its encryption service is never opened again. */
  released?: boolean;
  /** Encryption prepared per file index, for the given content (plain array: not reactive). */
  prepared: ({ file: Blob; size: Promise<number> } | undefined)[];
}

/** createTransfer body sealed for one submission, reused as is when it is retried. */
interface SealedBody {
  /** Serialized plaintext form of the submission (see submitTransfer). */
  signature: string;
  files: readonly Blob[];
  body: TransferCreate;
  state: E2EState;
  info: E2EFileInfo[];
}

/** Announcement steps of the preparation (percent). */
const PREPARE_ANNOUNCE_STEP = 10;

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
  if (status === 'not_scanned_e2e') return 'deposit.e2e.scanStatus';
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
    case 'not_scanned_disabled':
      return 'deposit.done.warning.notScanned';
    case 'not_scanned_e2e':
      // Neutral note: the sender chose the encryption knowing it excludes the antivirus.
      return 'deposit.e2e.notScanned';
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
    linkOnly: false,
    endToEnd: false,
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
  /** The drop link was revoked, disabled or rotated since the landing page. */
  dropLinkGone = $state(false);
  /** Reply mode: the reply session is gone (expired, ended or never opened). */
  replyEnded = $state(false);
  /**
   * Download link of a link-only transfer, taken from the answer of the finalization (the only
   * one that carries it, once). Kept apart from transfer: later reads replace that object.
   */
  linkOnlyUrl = $state<string | undefined>(undefined);
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
  /** Hash pass of an end-to-end encrypted transfer (step preparing). */
  preparation = $state.raw<Preparation | undefined>(undefined);
  /**
   * Transfer key (base64url) of the end-to-end encrypted transfer just delivered, shown once on
   * the done step; forgotten when the done step is left.
   */
  e2eKey = $state<string | undefined>(undefined);
  /** Real names (and plaintext SHA-256) of the files of the end-to-end encrypted transfer. */
  e2eFiles = $state.raw<E2EFileInfo[] | undefined>(undefined);

  readonly tenant: PublicTenant;
  readonly invitation: InvitationContext | undefined;
  readonly reply: ReplyContext | undefined;
  readonly dropLink: DropLinkContext | undefined;
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
  #prepareAbort: AbortController | undefined;
  /** Number of end-to-end encrypted submissions started (see submitTransfer). */
  #submissions = 0;
  /** Sealed body of the current submission (end-to-end encryption), until it is created. */
  #sealed: SealedBody | undefined;
  /** Encryption state of the transfer being uploaded. */
  #e2e: E2EState | undefined;
  #disposed = false;

  constructor(
    tenant: PublicTenant,
    invitation: InvitationContext | undefined,
    deps: DepositFlowDeps,
    reply?: ReplyContext,
    dropLink?: DropLinkContext,
  ) {
    this.tenant = tenant;
    this.reply = reply;
    this.dropLink = dropLink;
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
    if (dropLink !== undefined) {
      this.form.expiryDays = dropLink.validityDays;
    }
  }

  // ---- Derived values ---------------------------------------------------------------------

  /** The depositor is an invited external user: no recipients to choose. */
  get isExternal(): boolean {
    return this.session?.kind === 'external' || (this.session === undefined && this.invitation !== undefined);
  }

  /** The depositor deposits through a permanent drop link: the link fixes recipients and validity. */
  get isDropLink(): boolean {
    return this.session?.kind === 'drop_link' || (this.session === undefined && this.dropLink !== undefined);
  }

  /** Label of the drop link, shown as the destination of the files. */
  get dropLinkLabel(): string | undefined {
    return this.session?.dropLink?.label ?? this.dropLink?.label;
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
    if (this.dropLink !== undefined) {
      // The level is imposed by the link: the depositor cannot choose another one.
      const all = this.tenant.confidentialityLevels ?? [];
      const imposed =
        this.dropLink.levelKey === undefined ? defaultLevel(all) : levelByKey(all, this.dropLink.levelKey);
      return imposed === undefined ? [] : [imposed];
    }
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

  /** The "link only" option is offered: tenant feature, level not forbidding it, internal depositor. */
  get linkOnlyOffered(): boolean {
    return (
      this.tenant.features?.linkOnly === true &&
      this.rules?.linkOnlyAllowed !== false &&
      (this.session?.kind === 'internal' || this.session?.kind === 'internal_remote')
    );
  }

  /** The level requires recipient verification, which cannot be combined with a link-only transfer. */
  get linkOnlyBlockedByVerification(): boolean {
    return this.linkOnlyOffered && this.rules?.requireRecipientVerification === true;
  }

  /** Link-only as sent. */
  get linkOnlyEffective(): boolean {
    return this.linkOnlyOffered && !this.linkOnlyBlockedByVerification && this.form.linkOnly;
  }

  /** Chooses or clears link-only; choosing it clears the incompatible recipient verification. */
  setLinkOnly(on: boolean): void {
    this.form.linkOnly = on;
    if (on) this.form.recipientVerification = false;
  }

  /**
   * End-to-end encryption policy that applies: the effective policy of the chosen level when
   * the tenant has levels (already merged with the tenant's by the server), else the tenant's;
   * forbidden when absent, and always for a drop link (the server refuses it there).
   */
  get e2ePolicy(): E2ePolicy {
    if (this.isDropLink) return 'forbidden';
    const level = this.level;
    if (level !== undefined) return level.e2ePolicy ?? 'forbidden';
    return this.tenant.features?.e2ePolicy ?? 'forbidden';
  }

  /** The end-to-end encryption option is shown. */
  get e2eOffered(): boolean {
    return this.e2ePolicy !== 'forbidden';
  }

  /** End-to-end encryption is imposed (the option is checked and locked). */
  get e2eRequired(): boolean {
    return this.e2ePolicy === 'required';
  }

  /** End-to-end encryption as sent. */
  get e2eEffective(): boolean {
    return this.e2eOffered && (this.e2eRequired || this.form.endToEnd);
  }

  /** The transfer being uploaded is end-to-end encrypted. */
  get e2eActive(): boolean {
    return this.#e2e !== undefined;
  }

  /** Recipient verification as sent: forced by the level or chosen by the sender. */
  get recipientVerificationEffective(): boolean {
    if (this.form.linkOnly && this.linkOnlyOffered) return false;
    return effectiveRecipientVerification(
      this.form.recipientVerification,
      this.rules,
      this.recipientVerificationOffered,
    );
  }

  /** Durations offered: the one of the link for a drop link, else those the chosen level allows. */
  get expiryOptions(): number[] {
    if (this.dropLink !== undefined) {
      return [this.session?.dropLink?.validityDays ?? this.dropLink.validityDays];
    }
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
    if (!this.linkOnlyOffered || this.linkOnlyBlockedByVerification) this.form.linkOnly = false;
    if (!this.e2eOffered) this.form.endToEnd = false;
    this.form.expiryDays = keepExpiry(this.form.expiryDays, this.expiryOptions);
    this.form.maxDownloadsText = keepMaxDownloads(this.form.maxDownloadsText, this.rules);
  }

  /** Limits of the session (or of the tenant before identification). */
  get limits(): { maxTransferBytes: number; expiryDays: number[] } {
    return this.session?.limits ?? this.tenant.limits;
  }

  /**
   * Total size the transfer declares: that of the selected files, or of their encrypted streams
   * (slightly larger) with end-to-end encryption, which is what the size limit applies to.
   */
  get totalBytes(): number {
    const e2e = this.e2eEffective;
    return this.form.files.reduce((sum, f) => sum + (e2e ? encryptedSize(f.size) : f.size), 0);
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
    if (this.busy || this.invitationGone || this.dropLinkGone) return;
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
        this.invitation !== undefined
          ? { email, invitationToken: this.invitation.token }
          : this.dropLink !== undefined
            ? { email, dropLinkToken: this.dropLink.token }
            : { email };
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

  /** Adds picked files with their relative folder (see FileDrop folders mode). */
  addPicked(files: readonly AcceptedFile<DepositFile>[]): void {
    this.addFiles(files.map(withPath));
  }

  /** Tenant feature: folders can be sent. */
  get foldersEnabled(): boolean {
    return this.tenant.features?.folders === true;
  }

  /** Number of files that can still be added to the transfer. */
  get fileRoom(): number {
    return Math.max(0, MAX_FILES - this.form.files.length);
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
    const needRecipients =
      session.kind !== 'external' && session.kind !== 'reply' && session.kind !== 'drop_link';
    const linkOnly = this.linkOnlyEffective;
    const e2e = this.e2eEffective;
    // The size limit applies to the declared sizes: those of the encrypted streams with E2E.
    const checked = e2e
      ? { ...this.form, files: this.form.files.map((f) => ({ name: f.name, size: encryptedSize(f.size) })) }
      : this.form;
    const errors = {
      ...validateForm(
        checked,
        { ...session.limits, expiryDays: this.expiryOptions },
        needRecipients,
        linkOnly,
      ),
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
      files: files.map((f) => {
        const declared: TransferCreate['files'][number] = { name: f.name, size: f.size };
        if (f.path !== undefined && f.path !== '') declared.path = f.path;
        if (f.type !== '') declared.mediaType = f.type;
        return declared;
      }),
    };
    if (needRecipients) {
      const recipients = parseRecipients(this.form.recipientsText);
      // A link-only transfer may have none; the field is then left out.
      if (!linkOnly || recipients.length > 0) body.recipients = recipients;
    }
    if (linkOnly) body.linkOnly = true;
    if (this.form.message.trim() !== '') body.message = this.form.message;
    if (this.form.password !== '') body.password = this.form.password;
    if (this.maxDownloadsOffered) {
      const parsed = parseMaxDownloads(this.form.maxDownloadsText);
      if (parsed.ok && parsed.value !== undefined) body.maxDownloads = parsed.value;
    }
    if (this.recipientVerificationEffective) body.recipientVerification = true;
    // A drop link imposes its own level: the server refuses a choice made by the depositor.
    if (this.level !== undefined && session.kind !== 'drop_link') body.confidentialityLevel = this.level.key;
    const language = this.#deps.language();
    if ((languageValues as readonly string[]).includes(language)) {
      body.language = language as TransferCreate['language'];
    }
    if (e2e) body.endToEndEncrypted = true;
    // The key is kept across transient failures only while the request stays the same. With
    // end-to-end encryption the plaintext form is compared, and the body sealed for it (random
    // key, salts and nonces) is reused as is, so that a retry sends exactly the same request.
    const serialized = JSON.stringify(body);
    if (this.#lastBody !== undefined && this.#lastBody !== serialized) this.#renewKey();
    this.#lastBody = serialized;
    this.busy = true;
    let sealed: SealedBody | undefined;
    if (e2e) {
      const run = ++this.#submissions;
      sealed = this.#sealedFor(serialized, files) ?? (await this.#prepareE2E(serialized, body, files));
      if (sealed === undefined) {
        // A cancelled preparation may settle after the next submission has started.
        if (run === this.#submissions) this.busy = false;
        return;
      }
      this.#sealed = sealed;
    }
    let transfer: SenderTransfer;
    try {
      transfer = (
        await this.#deps.api.post('/transfers', {
          body: sealed?.body ?? body,
          headers: { 'Idempotency-Key': this.#key.value },
        })
      ).data;
    } catch (err) {
      this.busy = false;
      this.#transferError(err);
      return;
    }
    this.busy = false;
    const record: ResumeRecord = { transferId: transfer.id, files: files.map((f) => fingerprint(f)) };
    this.#clearE2E();
    this.e2eFiles = undefined;
    if (sealed !== undefined) {
      // The state now belongs to the upload: keep it out of #renewKey's reach.
      this.#sealed = undefined;
      this.#e2e = sealed.state;
      this.e2eFiles = sealed.info;
      record.e2e = {
        key: encodeKey(sealed.state.key),
        salts: sealed.state.salts.map(encodeBase64Url),
        sha256: sealed.info.map((f) => f.sha256 ?? ''),
        chunkSize: sealed.state.chunkSize,
      };
    }
    this.#renewKey();
    this.retryAt = undefined;
    this.#deps.resumeStore.save(record);
    this.form.password = '';
    this.#runUpload(transfer, files, true);
  }

  /**
   * Cancels the hash pass of an end-to-end encrypted transfer: back to the form, or to the resume
   * step when it was the check of the files reselected after a reload.
   */
  cancelPreparing(): void {
    if (this.#prepareAbort === undefined) return;
    const resuming = this.preparation?.kind === 'resume';
    this.#prepareAbort.abort();
    this.#prepareAbort = undefined;
    this.preparation = undefined;
    this.busy = false;
    this.step = resuming ? 'resume' : 'form';
    this.notice = {
      key: resuming ? 'deposit.e2e.preparing.resumeCancelled' : 'deposit.e2e.preparing.cancelled',
    };
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
    this.#clearE2E();
    this.e2eFiles = undefined;
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

  /** Adds reselected files with their relative folder on the resume step. */
  addResumePicked(files: readonly AcceptedFile<DepositFile>[]): void {
    this.addResumeFiles(files.map(withPath));
  }

  /**
   * Continues the interrupted upload with the reselected files. For an end-to-end encrypted
   * transfer every reselected file is first hashed again (step preparing) and compared with the
   * SHA-256 of the record: the fingerprint (name, size, date) does not prove the content, and a
   * different plaintext must never be encrypted with the stored key and salt. A file that differs
   * ends the transfer (deposit.e2e.resumeChanged): it is abandoned and the record dropped.
   */
  async continueResume(): Promise<void> {
    const record = this.resumeRecord;
    const transfer = this.transfer;
    if (this.busy || record === undefined || transfer === undefined || this.resumeMissing.length > 0) {
      return;
    }
    const match = matchFiles(record, this.resumeFiles);
    const state = this.#e2e;
    if (state !== undefined && record.e2e !== undefined) {
      const verdict = await this.#checkResumed(state, record.e2e.sha256, match.files);
      if (verdict === 'stopped' || this.#disposed || this.#e2e !== state) return;
      if (verdict === 'changed') {
        await this.#refuseChanged(transfer.id);
        return;
      }
    }
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
    this.#clearE2E();
    this.e2eFiles = undefined;
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
    this.linkOnlyUrl = undefined;
    this.#clearE2E();
    this.#cancelPrepare();
    this.e2eKey = undefined;
    this.e2eFiles = undefined;
    this.blockedFiles = undefined;
    this.finalizeError = undefined;
    this.stepError = undefined;
    this.notice = undefined;
    this.formErrors = {};
    this.form = emptyForm(
      this.dropLink === undefined ? this.limits.expiryDays : this.expiryOptions,
      this.levels,
    );
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
    this.linkOnlyUrl = undefined;
    this.e2eKey = undefined;
    this.#abortFinalize();
    this.#cancelPrepare();
    this.#disposeEngine();
    this.#clearE2E();
    this.#dropSealed();
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
    if (this.dropLink !== undefined) {
      // A drop link asks for its own code at every use: only a drop link session fits.
      return session.kind === 'drop_link' && session.dropLink?.label === this.dropLink.label;
    }
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
    // An encryption state left by an expired session is rebuilt from the resume record, if any.
    // The engine goes first: a chunk read after the release would reopen the service.
    this.#disposeEngine();
    this.#clearE2E();
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
        if ((transfer.endToEndEncrypted === true) !== (record.e2e !== undefined)) {
          // A record that does not match the transfer cannot regenerate its bytes.
          this.#deps.resumeStore.clear();
          this.step = 'form';
          return;
        }
        this.#restoreE2E(record);
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
          if (this.#e2e !== undefined && transfer.status === 'available') {
            this.e2eKey = encodeKey(this.#e2e.key);
          }
          this.#clearE2E();
          this.step = 'done';
          return;
        }
        this.#clearE2E();
        this.e2eFiles = undefined;
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
    } else if (isProblem(err, 'drop-link-invalid')) {
      this.dropLinkGone = true;
      this.challenge = undefined;
      this.step = 'email';
      this.stepError = { message: { key: 'deposit.email.dropLinkGone' } };
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
    } else if (isProblem(err, 'e2e-required') || isProblem(err, 'e2e-forbidden')) {
      this.formErrors = {
        endToEnd: { key: `deposit.e2e.${err.code === 'e2e-required' ? 'required' : 'forbidden'}` },
      };
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
    this.#dropSealed();
  }

  // ---- End-to-end encryption ----------------------------------------------------------------

  /** The sealed body of this very submission (same plaintext form, same files), if any. */
  #sealedFor(signature: string, files: readonly Blob[]): SealedBody | undefined {
    const sealed = this.#sealed;
    if (sealed === undefined || sealed.signature !== signature || sealed.files.length !== files.length) {
      return undefined;
    }
    return sealed.files.every((f, i) => f === files[i]) ? sealed : undefined;
  }

  /**
   * Draws the transfer key and the salts, hashes every file (step preparing, with progress) and
   * seals the metadata and the message into the createTransfer body. Returns undefined when the
   * preparation was cancelled or failed (the error is shown on the form).
   */
  async #prepareE2E(
    signature: string,
    plain: TransferCreate,
    files: readonly DepositFile[],
  ): Promise<SealedBody | undefined> {
    if (globalThis.crypto?.subtle === undefined) {
      this.stepError = { message: { key: 'deposit.e2e.unsupported' } };
      return undefined;
    }
    const controller = new AbortController();
    this.#prepareAbort = controller;
    const state: E2EState = {
      key: generateTransferKey(),
      salts: files.map(() => randomBytes(SALT_SIZE)),
      chunkSize: DEFAULT_CHUNK_SIZE,
      prepared: [],
    };
    const total = files.reduce((sum, f) => sum + f.size, 0);
    let before = 0;
    let announced = 0;
    const progress = (bytes: number): void => {
      if (controller.signal.aborted) return;
      const hashed = before + bytes;
      const percent = total === 0 ? 100 : Math.floor((hashed * 100) / total);
      this.preparation = { kind: 'create', hashedBytes: hashed, totalBytes: total, percent };
      if (
        percent < 100 &&
        Math.floor(percent / PREPARE_ANNOUNCE_STEP) > Math.floor(announced / PREPARE_ANNOUNCE_STEP)
      ) {
        announced = percent;
        this.#deps.announce(this.#deps.tr.t('deposit.e2e.preparing.announce', { percent }));
      }
    };
    this.preparation = { kind: 'create', hashedBytes: 0, totalBytes: total, percent: total === 0 ? 100 : 0 };
    this.step = 'preparing';
    try {
      const crypto = await this.#e2eCrypto(state);
      const hashes: string[] = [];
      for (const [i, file] of files.entries()) {
        hashes.push(await crypto.hash(i, file, state.chunkSize, progress, controller.signal));
        before += file.size;
      }
      const info = files.map((file, i) => ({ name: file.name, path: file.path ?? '', sha256: hashes[i] }));
      const count = files.length;
      const declared = await Promise.all(
        files.map(async (file, i) => ({
          name: e2eFileName(i),
          size: ciphertextSize(file.size, state.chunkSize),
          encryptedMetadata: await sealMetadata(state.key, i, {
            index: i,
            count,
            name: file.name,
            path: file.path ?? '',
            type: file.type,
            size: file.size,
            sha256: hashes[i] as string,
          }),
        })),
      );
      const body: TransferCreate = { ...plain, files: declared };
      delete body.message;
      if (plain.message !== undefined) body.encryptedMessage = await sealMessage(state.key, plain.message);
      if (controller.signal.aborted) throw new DOMException('aborted', 'AbortError');
      this.#prepareAbort = undefined;
      this.preparation = undefined;
      this.step = 'form';
      this.#deps.announce(this.#deps.tr.t('deposit.e2e.preparing.done'));
      return { signature, files, body, state, info };
    } catch (err) {
      this.#releaseCrypto(state);
      if (controller.signal.aborted || isAbortError(err) || this.#disposed) return undefined;
      this.#prepareAbort = undefined;
      this.preparation = undefined;
      this.step = 'form';
      this.stepError = { message: { key: 'deposit.e2e.prepareFailed' } };
      return undefined;
    }
  }

  /** The encryption service of state, opened on first use. */
  #e2eCrypto(state: E2EState): Promise<UploadCrypto> {
    if (state.released === true) return Promise.reject(new Error('upload crypto: released'));
    state.crypto ??= importTransferKey(state.key).then((key) =>
      (this.#deps.openCrypto ?? openUploadCrypto)(key),
    );
    return state.crypto;
  }

  /** Encrypted bytes [start, end) of file index, for the upload engine. */
  async #readEncrypted(
    state: E2EState,
    index: number,
    file: Blob,
    expectedSize: number,
    start: number,
    end: number,
  ): Promise<Uint8Array<ArrayBuffer>> {
    // A detached engine (state released or replaced) must not reopen the service.
    if (this.#e2e !== state) throw new Error('upload crypto: state replaced');
    try {
      return await this.#encryptedRange(state, index, file, expectedSize, start, end);
    } catch (err) {
      if (isFileChangedError(err)) throw new UploadError('file-changed');
      throw err;
    }
  }

  async #encryptedRange(
    state: E2EState,
    index: number,
    file: Blob,
    expectedSize: number,
    start: number,
    end: number,
  ): Promise<Uint8Array<ArrayBuffer>> {
    const crypto = await this.#e2eCrypto(state);
    let entry = state.prepared[index];
    if (entry?.file !== file) {
      // One salt per declared file (built with the files, or checked by isResumeRecord).
      const salt = state.salts[index] as Uint8Array;
      entry = { file, size: crypto.prepare(index, file, salt, state.chunkSize) };
      state.prepared[index] = entry;
    }
    if ((await entry.size) !== expectedSize) {
      throw new Error(`file ${index}: encrypted size differs from the declared one`);
    }
    return crypto.range(index, start, end);
  }

  /** Rebuilds the encryption state of an interrupted transfer from its resume record. */
  #restoreE2E(record: ResumeRecord): void {
    this.#clearE2E();
    const saved = record.e2e;
    if (saved === undefined) return;
    this.#e2e = {
      key: parseKey(saved.key),
      // isResumeRecord checked every salt.
      salts: saved.salts.map((salt) => decodeBase64Url(salt) as Uint8Array<ArrayBuffer>),
      chunkSize: saved.chunkSize,
      prepared: [],
    };
    this.e2eFiles = record.files.map((fp, i) => ({
      name: fp.name,
      path: fp.path ?? '',
      sha256: saved.sha256[i],
    }));
  }

  /**
   * Hashes the reselected files of an end-to-end encrypted transfer again (step preparing, kind
   * resume) and compares them with expected, the SHA-256 kept by the record. The pass also records
   * the chunk digests the encryption checks (UploadCryptoCore). Files absent (already complete on
   * the server) are skipped. Returns stopped when cancelled, the page left or the hash failed
   * (error shown on the resume step).
   */
  async #checkResumed(
    state: E2EState,
    expected: readonly string[],
    files: readonly (Blob | undefined)[],
  ): Promise<'same' | 'changed' | 'stopped'> {
    const controller = new AbortController();
    this.#prepareAbort = controller;
    this.busy = true;
    this.stepError = undefined;
    this.notice = undefined;
    const total = files.reduce((sum, f) => sum + (f?.size ?? 0), 0);
    let before = 0;
    const progress = (bytes: number): void => {
      if (controller.signal.aborted) return;
      const hashed = before + bytes;
      const percent = total === 0 ? 100 : Math.floor((hashed * 100) / total);
      this.preparation = { kind: 'resume', hashedBytes: hashed, totalBytes: total, percent };
    };
    this.preparation = { kind: 'resume', hashedBytes: 0, totalBytes: total, percent: total === 0 ? 100 : 0 };
    this.step = 'preparing';
    try {
      const crypto = await this.#e2eCrypto(state);
      for (const [i, file] of files.entries()) {
        if (file === undefined) continue;
        const hash = await crypto.hash(i, file, state.chunkSize, progress, controller.signal);
        if (controller.signal.aborted) return 'stopped';
        if (hash !== expected[i]) return 'changed';
        before += file.size;
      }
      if (controller.signal.aborted) return 'stopped';
      return 'same';
    } catch (err) {
      if (controller.signal.aborted || isAbortError(err) || this.#disposed) return 'stopped';
      this.step = 'resume';
      this.stepError = { message: { key: 'deposit.e2e.prepareFailed' } };
      return 'stopped';
    } finally {
      if (this.#prepareAbort === controller) {
        this.#prepareAbort = undefined;
        this.preparation = undefined;
        this.busy = false;
      }
    }
  }

  /** Ends a resume whose reselected file differs from the original: abandoned, record dropped. */
  async #refuseChanged(transferId: string): Promise<void> {
    this.#deps.resumeStore.clear();
    this.resumeRecord = undefined;
    this.resumeFiles = [];
    this.transfer = undefined;
    this.#clearE2E();
    this.e2eFiles = undefined;
    this.step = 'form';
    this.stepError = { message: { key: 'deposit.e2e.resumeChanged' } };
    this.#deps.announce(this.#deps.tr.t('deposit.e2e.resumeChanged'), 'assertive');
    // Best effort: the transfer expires on the server anyway (TT_UPLOAD_TTL).
    await this.#cancelOnServer(transferId, true);
  }

  /** Releases the Worker of state. */
  #releaseCrypto(state: E2EState): void {
    const crypto = state.crypto;
    state.crypto = undefined;
    state.released = true;
    state.prepared = [];
    crypto?.then(
      (c) => c.dispose(),
      () => {},
    );
  }

  /** Forgets the encryption state of the transfer being uploaded. */
  #clearE2E(): void {
    if (this.#e2e !== undefined) this.#releaseCrypto(this.#e2e);
    this.#e2e = undefined;
  }

  /** Forgets the body sealed for a submission that will not be retried. */
  #dropSealed(): void {
    if (this.#sealed !== undefined) this.#releaseCrypto(this.#sealed.state);
    this.#sealed = undefined;
  }

  /** Aborts a hash pass in progress (page left, new transfer). */
  #cancelPrepare(): void {
    this.#prepareAbort?.abort();
    this.#prepareAbort = undefined;
    this.preparation = undefined;
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
    const specs = uploadSpecs(transfer, contents, fresh);
    const state = this.#e2e;
    if (state !== undefined) {
      specs.forEach((spec, i) => {
        // The plaintext is never handed to the engine: its size is not the declared one.
        const content = spec.file;
        delete spec.file;
        const info = this.e2eFiles?.[i];
        if (info !== undefined) spec.name = fullName(info.path, info.name);
        if (content !== undefined) {
          const expected = spec.size ?? 0;
          spec.readChunk = (start, end) => this.#readEncrypted(state, i, content, expected, start, end);
        }
      });
    }
    const engine = this.#deps.createEngine(specs, async () => {
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
        if (controller.signal.aborted) return;
        this.transfer = t;
        this.#captureLink(t);
      },
    });
    if (controller.signal.aborted || this.#disposed) return;
    this.#finalizeAbort = undefined;
    switch (outcome.kind) {
      case 'available':
      case 'rejected':
        this.transfer = outcome.transfer;
        this.#captureLink(outcome.transfer);
        this.outcome = outcome.kind;
        this.#deps.resumeStore.clear();
        this.#disposeEngine();
        if (this.#e2e !== undefined && outcome.kind === 'available') this.e2eKey = encodeKey(this.#e2e.key);
        this.#clearE2E();
        this.step = 'done';
        this.#deps.announce(
          this.#deps.tr.t(
            outcome.kind === 'rejected'
              ? 'upload.finalize.rejected'
              : outcome.transfer.linkOnly === true
                ? 'upload.finalize.availableLinkOnly'
                : 'upload.finalize.available',
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

  /** Keeps the link of a link-only transfer the first time an answer carries it. */
  #captureLink(transfer: SenderTransfer): void {
    if (transfer.linkOnly === true && transfer.downloadUrl && this.linkOnlyUrl === undefined) {
      this.linkOnlyUrl = transfer.downloadUrl;
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

/** Size of the encrypted stream of a plaintext of size bytes (DEFAULT_CHUNK_SIZE chunks). */
export function encryptedSize(size: number): number {
  return ciphertextSize(size, DEFAULT_CHUNK_SIZE);
}
