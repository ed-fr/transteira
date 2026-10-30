// View models of the public screens other than the deposit: classification of API errors into
// page states, and the download file list with filtered links. Pure functions, unit tested.
import { ApiProblem, NetworkError } from '../../shared/api/client';
import type { components } from '../../shared/api/schema';
import { safeApiHref } from '../../shared/safe/href';

/** Transfer as seen by a recipient. */
export type PublicTransfer = components['schemas']['PublicTransfer'];

/** One deliverable file of a transfer. */
export type PublicFile = components['schemas']['PublicFile'];

/** Invitation as seen by the invited person. */
export type PublicInvitation = components['schemas']['PublicInvitation'];

/** Antivirus status of a file. */
export type ScanStatus = components['schemas']['ScanStatus'];

/** Page state after a failed GET of a token resource (download, invitation, legal page). */
export type LoadFailure = 'not-found' | 'gone' | 'error';

/** Classifies the error of a GET on a token resource: 404, 410, anything else. */
export function loadFailure(err: unknown): LoadFailure {
  if (err instanceof ApiProblem) {
    if (err.status === 404) {
      return 'not-found';
    }
    if (err.status === 410) {
      return 'gone';
    }
  }
  return 'error';
}

/** Page state after a failed GET of a download link: also the maximum number of downloads. */
export type DownloadLoadFailure = LoadFailure | 'max-downloads';

/** Classifies the error of a GET of a download link: 410 max-downloads-reached is its own state. */
export function downloadLoadFailure(err: unknown): DownloadLoadFailure {
  if (err instanceof ApiProblem && err.status === 410 && err.code === 'max-downloads-reached') {
    return 'max-downloads';
  }
  return loadFailure(err);
}

/** Outcome of a failed POST /downloads/{token}/unlock. */
export type UnlockFailure =
  | { kind: 'wrong'; attemptsRemaining: number | undefined }
  | { kind: 'locked'; retryAfterSeconds: number | undefined }
  | { kind: 'required' }
  | { kind: 'verification-required' }
  | { kind: 'not-found' }
  | { kind: 'gone' }
  | { kind: 'max-downloads' }
  | { kind: 'error' };

/** Classifies the error of an unlock attempt. */
export function unlockFailure(err: unknown): UnlockFailure {
  if (!(err instanceof ApiProblem)) {
    return { kind: 'error' };
  }
  switch (err.status) {
    case 400:
      return { kind: 'required' };
    case 401:
      // The recipient verification cookie expired (1 hour): back to the verification step.
      return err.code === 'recipient-verification-required'
        ? { kind: 'verification-required' }
        : { kind: 'wrong', attemptsRemaining: err.attemptsRemaining };
    case 404:
      return { kind: 'not-found' };
    case 410:
      return err.code === 'max-downloads-reached' ? { kind: 'max-downloads' } : { kind: 'gone' };
    case 429:
      return { kind: 'locked', retryAfterSeconds: err.retryAfterSeconds };
    default:
      return { kind: 'error' };
  }
}

/** The recipient must prove their address by code before anything else (per-recipient link). */
export function needsVerification(transfer: PublicTransfer): boolean {
  return transfer.verificationRequired === true && transfer.verified !== true;
}

/** Transfer no longer available, as found by the verification step. */
export type VerificationGone = 'not-found' | 'gone' | 'max-downloads';

/** Outcome of a failed POST /downloads/{token}/verification (ask for a code). */
export type VerificationStartFailure =
  | { kind: 'rate-limited'; retryAfterSeconds: number | undefined }
  | { kind: 'mail-unavailable' }
  | { kind: 'conflict' }
  | { kind: 'maintenance' }
  | { kind: VerificationGone }
  | { kind: 'error' };

/** Classifies the error of a request for a recipient verification code. */
export function verificationStartFailure(err: unknown): VerificationStartFailure {
  if (!(err instanceof ApiProblem)) {
    return { kind: 'error' };
  }
  switch (err.status) {
    case 404:
      return { kind: 'not-found' };
    case 409:
      return { kind: 'conflict' };
    case 410:
      return err.code === 'max-downloads-reached' ? { kind: 'max-downloads' } : { kind: 'gone' };
    case 429:
      return { kind: 'rate-limited', retryAfterSeconds: err.retryAfterSeconds };
    case 503:
      return err.code === 'maintenance' ? { kind: 'maintenance' } : { kind: 'mail-unavailable' };
    default:
      return { kind: 'error' };
  }
}

/** Outcome of a failed POST /downloads/{token}/verification/confirm (code entry). */
export type VerificationConfirmFailure =
  | { kind: 'wrong'; attemptsRemaining: number | undefined }
  | { kind: 'exhausted' }
  | { kind: 'no-code' }
  | { kind: 'rate-limited'; retryAfterSeconds: number | undefined }
  | { kind: VerificationGone }
  | { kind: 'error' };

/**
 * Classifies the error of a code entry. A wrong code is recognised by its code (the contract
 * documents 422, a 401 is accepted too); the code is exhausted after 2 wrong attempts (410), and
 * a 409 means that no code is pending (expired or already used): a new one must be requested.
 */
export function verificationConfirmFailure(err: unknown): VerificationConfirmFailure {
  if (!(err instanceof ApiProblem)) {
    return { kind: 'error' };
  }
  if (err.code === 'verification-code-invalid') {
    return { kind: 'wrong', attemptsRemaining: err.attemptsRemaining };
  }
  if (err.code === 'verification-exhausted') {
    return { kind: 'exhausted' };
  }
  switch (err.status) {
    case 400:
      return { kind: 'wrong', attemptsRemaining: undefined };
    case 404:
      return { kind: 'not-found' };
    case 409:
      return { kind: 'no-code' };
    case 410:
      return err.code === 'max-downloads-reached' ? { kind: 'max-downloads' } : { kind: 'gone' };
    case 422:
      return { kind: 'wrong', attemptsRemaining: err.attemptsRemaining };
    case 429:
      return { kind: 'rate-limited', retryAfterSeconds: err.retryAfterSeconds };
    default:
      return { kind: 'error' };
  }
}

/** Code as typed: spaces and separators removed, so that a pasted "123 456" is accepted. */
export function normalizeCode(value: string): string {
  return value.replace(/\s+/g, '');
}

/** Outcome of a failed POST /invitations. */
export type InviteFailure =
  | { kind: 'invalid'; fields: readonly string[] }
  | { kind: 'session' }
  | { kind: 'not-allowed' }
  | { kind: 'refused' }
  | { kind: 'rate-limited'; retryAfterSeconds: number | undefined }
  | { kind: 'maintenance' }
  | { kind: 'error' };

/**
 * Classifies the error of an invitation request. A 403 invitation-not-allowed means the
 * depositor is not internal (not-allowed). Any other 403 (deposit-not-allowed) is deliberately
 * generic: the inviter or the invited address is blocklisted, or the inviter no longer meets the
 * network rule (refused); the message shown must reveal neither the blocklist nor blame the
 * inviter.
 */
export function inviteFailure(err: unknown): InviteFailure {
  if (!(err instanceof ApiProblem)) {
    return { kind: 'error' };
  }
  switch (err.status) {
    case 400:
      return { kind: 'invalid', fields: (err.errors ?? []).map((e) => e.field) };
    case 401:
      return { kind: 'session' };
    case 403:
      if (err.code === 'csrf-invalid') {
        return { kind: 'session' };
      }
      return err.code === 'invitation-not-allowed' ? { kind: 'not-allowed' } : { kind: 'refused' };
    case 429:
      return { kind: 'rate-limited', retryAfterSeconds: err.retryAfterSeconds };
    case 503:
      return { kind: 'maintenance' };
    default:
      return { kind: 'error' };
  }
}

/** Reports whether an error means "no deposit session" (GET /deposit-sessions/current). */
export function isNoSession(err: unknown): boolean {
  return err instanceof ApiProblem && err.status === 401;
}

/** Reports whether an error is a network failure (no HTTP answer). */
export function isNetworkFailure(err: unknown): boolean {
  return err instanceof NetworkError;
}

/** Statuses of files delivered without antivirus analysis. */
export const NOT_SCANNED: readonly ScanStatus[] = [
  'not_scanned_too_large',
  'not_scanned_encrypted',
  'not_scanned_disabled',
];

/** Reports whether a file was delivered without antivirus analysis. */
export function isNotScanned(status: ScanStatus): boolean {
  return NOT_SCANNED.includes(status);
}

/** One row of the download file table. */
export interface FileRow {
  id: string;
  name: string;
  /** Relative folder of the file in the transfer; absent for the root. */
  path?: string | undefined;
  size: number;
  sha256: string;
  scanStatus: ScanStatus;
  /** Filtered download link; undefined when the server URL was rejected. */
  href: string | undefined;
}

/** Download view of an unlocked transfer. */
export interface DownloadView {
  files: FileRow[];
  totalBytes: number;
  /** Filtered archive link; undefined when absent or rejected. */
  archiveHref: string | undefined;
  /** At least one file was not analysed by the antivirus. */
  hasUnscanned: boolean;
  deleteAfterFirstDownload: boolean;
  /** Label of the confidentiality level, when the transfer has one. */
  levelLabel: string | undefined;
  /** Downloads left before the maximum is reached, when the transfer has a limit. */
  downloadsRemaining: number | undefined;
}

/** Builds the download view of a transfer (every API URL goes through safeApiHref). */
export function downloadView(transfer: PublicTransfer): DownloadView {
  const files: FileRow[] = (transfer.files ?? []).map((f) => ({
    id: f.id,
    name: f.name,
    ...(f.path === undefined ? {} : { path: f.path }),
    size: f.size,
    sha256: f.sha256,
    scanStatus: f.scanStatus,
    href: safeApiHref(f.downloadUrl),
  }));
  const total = transfer.totalBytes ?? files.reduce((sum, f) => sum + Math.max(0, f.size), 0);
  return {
    files,
    totalBytes: total,
    archiveHref: files.length > 0 ? safeApiHref(transfer.archiveUrl) : undefined,
    hasUnscanned: files.some((f) => isNotScanned(f.scanStatus)),
    deleteAfterFirstDownload: transfer.deleteAfterFirstDownload === true,
    levelLabel: transfer.confidentialityLevel?.label,
    downloadsRemaining: transfer.downloadsRemaining,
  };
}

/** Minimum time between two checks of the download page state on window focus. */
export const RECHECK_INTERVAL_MS = 60_000;

/**
 * Reports whether the download page should read the transfer again when the window gets the
 * focus back: the download grant of a password-protected transfer lasts one hour, and the
 * transfer may have expired or been deleted meanwhile. At most one check per interval.
 */
export function shouldRecheck(lastCheckAt: number, now: number, intervalMs = RECHECK_INTERVAL_MS): boolean {
  return now - lastCheckAt >= intervalMs;
}

/** Maximum length of an invitation message (InvitationCreate.message). */
export const INVITATION_MESSAGE_MAX = 2000;

/** Loose client check of an email address (the server validates for real). */
export function looksLikeEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

/** The recipient may reply to this transfer (button on the download page). */
export function canReply(transfer: PublicTransfer): boolean {
  return transfer.replyAllowed === true && transfer.reply !== true && transfer.locked !== true;
}

/** Outcome of a failed POST /downloads/{token}/reply. */
export type ReplyFailure =
  | { kind: 'verification-required' }
  | { kind: 'not-allowed' }
  | { kind: 'deposit-not-allowed' }
  | { kind: 'maintenance' }
  | { kind: 'rate-limited' }
  | { kind: 'not-found' }
  | { kind: 'gone' }
  | { kind: 'max-downloads' }
  | { kind: 'error' };

/** Classifies the error of a request to open a reply session. */
export function replyFailure(err: unknown): ReplyFailure {
  if (!(err instanceof ApiProblem)) {
    return { kind: 'error' };
  }
  switch (err.status) {
    case 401:
      return err.code === 'recipient-verification-required'
        ? { kind: 'verification-required' }
        : { kind: 'error' };
    case 403:
      return err.code === 'deposit-not-allowed' ? { kind: 'deposit-not-allowed' } : { kind: 'not-allowed' };
    case 404:
      return { kind: 'not-found' };
    case 410:
      return err.code === 'max-downloads-reached' ? { kind: 'max-downloads' } : { kind: 'gone' };
    case 429:
      return { kind: 'rate-limited' };
    case 503:
      return err.code === 'maintenance' ? { kind: 'maintenance' } : { kind: 'error' };
    default:
      return { kind: 'error' };
  }
}
