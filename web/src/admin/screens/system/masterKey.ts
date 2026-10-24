// View model of the master key screen (super admin; CLAUDE.md section 16.1, threat model T-169).
// Pure functions only: the screen (MasterKey.svelte) renders them.
//
// - State of the screen from GET /admin/system/master-key (screenState): no new key configured,
//   ready to start, running, interrupted (a running rotation that no longer progresses), a
//   rotation between other keys, completed with a restart required, failed.
// - Progress of a rotation (progressView), clamped to 100 % since rewrappedKeys can exceed
//   totalKeys, and its screen reader announcements at 25/50/75/100 % only (milestone).
// - Detection of an interrupted rotation (observeProgress, isStalled): the API cannot say
//   whether the background worker runs. A rotation interrupted by a restart stays "running" in
//   the database and its counter no longer moves; a start request then resumes it (same id).
// - Polling cadence (pollDelay), handling of a failed read (pollErrorAction) and halts of the
//   polling by the screen (pollHalted): after a persistent error, or while the admin is idle
//   (activity.ts: a read extends the admin session, so no timer-driven read after 10 minutes
//   without activity, threat model T-165); a halt holds until a user action or another rotation.
// - Start request: body of the TOTP or recovery code (startBody) and mapping of its errors
//   (startFailure, conflictKind).
//
// Secrets: the typed code is passed in and never kept here. The API only returns key
// identifiers (mk_ + 16 hex characters, not secret), counts and dates: no key material.
import { ApiProblem } from '../../../shared/api/client';
import type { ErrorView } from '../../../shared/api/problem';
import type { components } from '../../../shared/api/schema';
import type { Translate } from '../../../shared/i18n/messages';
import type { ActivityTracker } from '../../activity';
import {
  normalizeRecoveryCode,
  normalizeTotpCode,
  recoveryCodeError,
  totpCodeError,
  totpFailure,
  type FieldError,
  type FormFailure,
  type Message,
} from '../../auth/views';

export type { Translate };

/** State of the master keys (GET /admin/system/master-key). */
export type MasterKeyStatus = components['schemas']['MasterKeyStatus'];
/** A master key rotation. */
export type KeyRotation = components['schemas']['KeyRotation'];
/** Body of the start request (one of code or recoveryCode). */
export type TotpCodeBody = { code: string } | { recoveryCode: string };

/** Documentation of the master key life cycle, shown as a path (no external link). */
export const MASTER_KEY_DOC = 'docs/operations/master-key.md';

// ---- Screen state --------------------------------------------------------------------------

/** What the screen shows. */
export type ScreenKind =
  /** No TT_MASTER_KEY_NEW_FILE: steps 1 and 2 explained, no start button. */
  | 'noNewKey'
  /** A new key is configured and no rotation runs: checklist and start button. */
  | 'ready'
  /** A rotation between the configured keys runs: progress, polling. */
  | 'running'
  /** A rotation between the configured keys stays running but no longer progresses: resume. */
  | 'interrupted'
  /** A running rotation between other keys: to finish or abandon with the command line. */
  | 'otherRotation'
  /** The rotation to the new key completed: next steps (switch the configuration, restart). */
  | 'restartRequired'
  /** The latest rotation failed: its error, and a new start is possible. */
  | 'failed';

/** Reports whether a rotation runs between the configured keys (current to new). */
export function matchesConfiguredKeys(status: MasterKeyStatus, rotation: KeyRotation): boolean {
  return (
    status.newKeyId !== undefined &&
    rotation.fromKeyId === status.activeKeyId &&
    rotation.toKeyId === status.newKeyId
  );
}

/**
 * State of the screen. stalled tells that the running rotation has not progressed for a while
 * (see isStalled). The order follows the checks of the server: a running rotation first (it
 * blocks or is resumed), then the restart required, then the new key.
 */
export function screenState(status: MasterKeyStatus, stalled: boolean): ScreenKind {
  const latest = status.latestRotation;
  if (latest?.status === 'running') {
    if (!matchesConfiguredKeys(status, latest)) {
      return 'otherRotation';
    }
    return stalled ? 'interrupted' : 'running';
  }
  if (status.restartRequired) {
    return 'restartRequired';
  }
  if (status.newKeyId === undefined) {
    return 'noNewKey';
  }
  return latest?.status === 'failed' ? 'failed' : 'ready';
}

/** Reports whether the screen offers to start (or resume) the rotation. */
export function canStart(kind: ScreenKind): boolean {
  return kind === 'ready' || kind === 'failed' || kind === 'interrupted';
}

/** Label key of the start button for a state that allows it. */
export function startLabelKey(kind: ScreenKind): string {
  switch (kind) {
    case 'interrupted':
      return 'sysMasterKey.start.resume';
    case 'failed':
      return 'sysMasterKey.start.again';
    default:
      return 'sysMasterKey.start.button';
  }
}

/** Reports whether the screen must poll the progress of the latest rotation. */
export function shouldPoll(status: MasterKeyStatus | undefined): boolean {
  return status?.latestRotation?.status === 'running';
}

/** Label key of the status of a rotation. */
export function rotationStatusKey(status: KeyRotation['status']): string {
  switch (status) {
    case 'completed':
      return 'sysMasterKey.latest.statuses.completed';
    case 'failed':
      return 'sysMasterKey.latest.statuses.failed';
    default:
      return 'sysMasterKey.latest.statuses.running';
  }
}

/** Badge variant of the status of a rotation (the label also names it: not colour only). */
export function rotationStatusVariant(status: KeyRotation['status']): 'info' | 'ok' | 'error' {
  switch (status) {
    case 'completed':
      return 'ok';
    case 'failed':
      return 'error';
    default:
      return 'info';
  }
}

/** Status with the latest rotation replaced by a fresher read of the same rotation. */
export function withRotation(status: MasterKeyStatus, rotation: KeyRotation): MasterKeyStatus {
  return { ...status, latestRotation: rotation };
}

/** Reports whether both checklist boxes are ticked (required before the start dialog). */
export function checklistDone(vaultCopy: boolean, idsChecked: boolean): boolean {
  return vaultCopy && idsChecked;
}

// ---- Progress ------------------------------------------------------------------------------

/** Display of the progress of a rotation. */
export interface ProgressView {
  /** Percentage (0 to 100, rounded down), undefined for an indeterminate bar. */
  percent: number | undefined;
  /** Keys re-wrapped so far (can exceed total). */
  done: number;
  /** Keys to re-wrap when the rotation started. */
  total: number;
}

/**
 * Progress of a rotation, clamped to 100 %: rewrappedKeys can exceed totalKeys (keys created
 * under the old key meanwhile). With totalKeys 0, a running rotation is indeterminate and a
 * finished one 100 %.
 */
export function progressView(rotation: KeyRotation): ProgressView {
  const done = Math.max(0, rotation.rewrappedKeys);
  const total = Math.max(0, rotation.totalKeys);
  let percent: number | undefined;
  if (total > 0) {
    percent = Math.min(100, Math.floor((done * 100) / total));
  } else if (rotation.status === 'completed') {
    percent = 100;
  }
  return { percent, done, total };
}

/** Text of the progress ("N keys re-wrapped out of M"). */
export function progressText(view: ProgressView, t: Translate, formatNumber: (n: number) => string): string {
  return t('sysMasterKey.progress.text', { done: formatNumber(view.done), total: formatNumber(view.total) });
}

/** Milestones announced to screen readers. */
export const MILESTONES = [25, 50, 75, 100] as const;

/** Highest milestone reached by percent (0 below the first one or when indeterminate). */
export function milestone(percent: number | undefined): number {
  let reached = 0;
  for (const m of MILESTONES) {
    if (percent !== undefined && percent >= m) {
      reached = m;
    }
  }
  return reached;
}

/** Announcement state of a rotation: the last milestone and status announced. */
export interface AnnounceState {
  rotationId: string;
  milestone: number;
  status: KeyRotation['status'];
}

/** Result of announceProgress: the new state and the message to announce, if any. */
export interface AnnounceStep {
  state: AnnounceState;
  message?: Message;
}

/**
 * Announcement for a new read of a rotation. A start (or resumption) by this page (started)
 * announces that the rotation runs; otherwise the first read of a rotation (page load) only
 * sets the baseline, silently. Afterwards: completion or failure once, and a milestone
 * each time a higher one is reached while running. Never on every poll.
 */
export function announceProgress(
  previous: AnnounceState | undefined,
  rotation: KeyRotation,
  started = false,
): AnnounceStep {
  const state: AnnounceState = {
    rotationId: rotation.id,
    milestone: milestone(progressView(rotation).percent),
    status: rotation.status,
  };
  if (started) {
    return { state, message: { key: 'sysMasterKey.announce.started' } };
  }
  if (previous === undefined || previous.rotationId !== rotation.id) {
    return { state };
  }
  if (previous.status === 'running' && rotation.status === 'completed') {
    return { state, message: { key: 'sysMasterKey.announce.completed' } };
  }
  if (previous.status === 'running' && rotation.status === 'failed') {
    return { state, message: { key: 'sysMasterKey.announce.failed' } };
  }
  if (rotation.status === 'running' && state.milestone > previous.milestone) {
    return {
      state,
      message: { key: 'sysMasterKey.announce.milestone', params: { percent: state.milestone } },
    };
  }
  return { state: { ...state, milestone: Math.max(state.milestone, previous.milestone) } };
}

// ---- Interruption --------------------------------------------------------------------------

/** Time without progress after which a running rotation is considered interrupted. */
export const STALL_MS = 30_000;
/** Consecutive reads without progress required as well (so one late read is not enough). */
export const STALL_READS = 3;

/** Progress watch of a running rotation. */
export interface ProgressWatch {
  rotationId: string;
  rewrappedKeys: number;
  /** Clock time (epoch ms) of the first read or of the last change of the counter. */
  changedAt: number;
  /** Successful reads since then with the same counter. */
  unchanged: number;
}

/** Updates the watch with a successful read of rotation at now (resets on another rotation). */
export function observeProgress(
  watch: ProgressWatch | undefined,
  rotation: KeyRotation,
  now: number,
): ProgressWatch {
  if (
    watch === undefined ||
    watch.rotationId !== rotation.id ||
    watch.rewrappedKeys !== rotation.rewrappedKeys
  ) {
    return { rotationId: rotation.id, rewrappedKeys: rotation.rewrappedKeys, changedAt: now, unchanged: 0 };
  }
  return { ...watch, unchanged: watch.unchanged + 1 };
}

/**
 * Reports whether the watched rotation looks interrupted: its counter has not changed for
 * STALL_MS and over STALL_READS successful reads. The worker re-wraps in short batches, so a
 * live rotation moves well within that time; a rotation interrupted by a restart (or stopped
 * on an error that leaves it running) does not. A false positive is harmless: when the worker
 * of this server instance runs the rotation, a resumption is refused (409, already running);
 * when another process runs it (the rotate-master-key command), the resumption runs alongside
 * it safely (conditional updates of each key, the worker that finds the rotation finished
 * elsewhere stops): the work is only done twice in part.
 */
export function isStalled(watch: ProgressWatch | undefined, now: number): boolean {
  return watch !== undefined && watch.unchanged >= STALL_READS && now - watch.changedAt >= STALL_MS;
}

// ---- Polling -------------------------------------------------------------------------------

/** Interval between two reads while the page is visible. */
export const POLL_MS = 2_000;
/** Interval while the page is hidden, or once the rotation looks interrupted. */
export const SLOW_POLL_MS = 10_000;
/** Longest wait after failed reads. */
export const MAX_BACKOFF_MS = 30_000;

/** Delay before the next read. errors counts the consecutive failed reads. */
export function pollDelay(options: { visible: boolean; stalled: boolean; errors: number }): number {
  const base = options.visible && !options.stalled ? POLL_MS : SLOW_POLL_MS;
  if (options.errors <= 0) {
    return base;
  }
  return Math.max(base, Math.min(MAX_BACKOFF_MS, POLL_MS * 2 ** options.errors));
}

/** Why the screen halted the polling of a rotation (other than a final status). */
export type PollHaltReason =
  /** No user activity for IDLE_PAUSE_MS (activity.ts): "Resume updates". */
  | 'idle'
  /** A read failed with an error that is not worth retrying (pollErrorAction): "Retry". */
  | 'error';

/** A halt of the polling, for one rotation. */
export interface PollHalt {
  reason: PollHaltReason;
  rotationId: string;
}

/**
 * Reports whether halt still stops the polling of rotationId. A halt holds across the reloads
 * of the status (they must not restart a read every 2 s after a persistent error) and ends
 * only on a user action (the screen clears it) or when another rotation is shown.
 */
export function pollHalted(halt: PollHalt | undefined, rotationId: string): boolean {
  return halt !== undefined && halt.rotationId === rotationId;
}

/**
 * Halt to apply before a timer-driven read of rotationId: idle once the admin has been inactive
 * for IDLE_PAUSE_MS (the read would extend the session of an unattended page), none otherwise.
 */
export function idleHalt(
  activity: Pick<ActivityTracker, 'isIdle'>,
  rotationId: string,
): PollHalt | undefined {
  return activity.isIdle() ? { reason: 'idle', rotationId } : undefined;
}

/**
 * What to do after a failed read of the progress: retry (with backoff) on a network error or a
 * server error, stop otherwise (session ended, forbidden, unknown rotation: the screen reloads
 * the status or the client goes back to the sign-in).
 */
export function pollErrorAction(view: ErrorView): 'retry' | 'stop' {
  return view.status === undefined || view.status >= 500 ? 'retry' : 'stop';
}

// ---- Start ---------------------------------------------------------------------------------

/** Kind of code typed in the dialog. */
export type CodeMode = 'totp' | 'recovery';

/** Client-side error of the typed code (same rules as the sign-in). */
export function codeError(mode: CodeMode, raw: string): FieldError | undefined {
  return mode === 'totp' ? totpCodeError(raw) : recoveryCodeError(raw);
}

/** Body of the start request (TotpCode). */
export function startBody(mode: CodeMode, raw: string): TotpCodeBody {
  return mode === 'totp' ? { code: normalizeTotpCode(raw) } : { recoveryCode: normalizeRecoveryCode(raw) };
}

/** Case of a 409 state-conflict of the start request. */
export type ConflictKind = 'running' | 'otherKeys' | 'restartRequired' | 'unknown';

/**
 * Case of a 409 state-conflict. The problem has no machine-readable member for it: the
 * server's detail names the case, matched first; otherwise the status read after the refusal
 * tells. The details are the constants detailRotationRunning, detailRotationMismatch and
 * detailRestartRequired of internal/api/admin/system.go (also in the OpenAPI examples), pinned
 * by TestRotationConflictDetails in internal/api/admin/system_test.go: keep both in sync.
 */
export function conflictKind(detail: string | undefined, status: MasterKeyStatus | undefined): ConflictKind {
  const text = (detail ?? '').toLowerCase();
  if (text.includes('already running')) {
    return 'running';
  }
  if (text.includes('other keys')) {
    return 'otherKeys';
  }
  if (text.includes('restart')) {
    return 'restartRequired';
  }
  if (status === undefined) {
    return 'unknown';
  }
  const latest = status.latestRotation;
  if (latest?.status === 'running') {
    return matchesConfiguredKeys(status, latest) ? 'running' : 'otherKeys';
  }
  return status.restartRequired ? 'restartRequired' : 'unknown';
}

/** How the screen shows a failed start request. */
export type StartFailure =
  /** Shown in the dialog, which stays open (wrong code, lock, malformed code, network). */
  | { kind: 'form'; failure: FormFailure }
  /** The dialog closes; the message is shown on the page; reload: read the status again. */
  | { kind: 'page'; message: Message; reload: boolean };

/** detail of an API problem, when the error is one. */
export function problemDetail(err: unknown): string | undefined {
  return err instanceof ApiProblem ? err.problem?.detail : undefined;
}

/** Message of a 409 state-conflict. */
export function conflictMessage(kind: ConflictKind, detail: string | undefined): Message {
  switch (kind) {
    case 'running':
      return { key: 'sysMasterKey.errors.running' };
    case 'otherKeys':
      return { key: 'sysMasterKey.errors.otherKeys' };
    case 'restartRequired':
      return { key: 'sysMasterKey.errors.restartRequired' };
    default:
      return detail !== undefined && detail !== '' ? { text: detail } : { key: 'errors.state-conflict' };
  }
}

/**
 * Display of a failed start request. status is the status read after a 409 (undefined
 * otherwise), used when the detail does not name the case.
 *
 * - 401 invalid-credentials: wrong code, with the attempts left when given (dialog);
 * - 429 rate-limited: lock with its countdown (dialog);
 * - 400 validation-failed: code format (dialog);
 * - 409 new-master-key-missing and state-conflict: page message, status read again;
 * - 403 forbidden, 401 unauthenticated (the client goes back to the sign-in): page message;
 * - anything else (network, server error): general message in the dialog.
 */
export function startFailure(
  view: ErrorView,
  detail: string | undefined,
  status: MasterKeyStatus | undefined,
): StartFailure {
  switch (view.code) {
    case 'invalid-credentials':
    case 'rate-limited':
    case 'validation-failed':
      return { kind: 'form', failure: totpFailure(view, 'login') };
    case 'new-master-key-missing':
      return { kind: 'page', message: { key: 'sysMasterKey.errors.newKeyMissing' }, reload: true };
    case 'state-conflict':
      return { kind: 'page', message: conflictMessage(conflictKind(detail, status), detail), reload: true };
    case 'forbidden':
    case 'unauthenticated':
      return { kind: 'page', message: { text: view.message }, reload: false };
    default:
      return { kind: 'form', failure: { general: { text: view.message }, fields: {} } };
  }
}
