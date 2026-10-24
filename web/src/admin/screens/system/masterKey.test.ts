import { describe, expect, it } from 'vitest';
import { ApiProblem } from '../../../shared/api/client';
import type { ErrorView } from '../../../shared/api/problem';
import { IDLE_PAUSE_MS, createActivityTracker } from '../../activity';
import {
  MAX_BACKOFF_MS,
  POLL_MS,
  SLOW_POLL_MS,
  STALL_MS,
  STALL_READS,
  announceProgress,
  canStart,
  checklistDone,
  codeError,
  conflictKind,
  conflictMessage,
  idleHalt,
  isStalled,
  matchesConfiguredKeys,
  milestone,
  observeProgress,
  pollDelay,
  pollErrorAction,
  pollHalted,
  problemDetail,
  progressText,
  progressView,
  rotationStatusKey,
  rotationStatusVariant,
  screenState,
  shouldPoll,
  startBody,
  startFailure,
  startLabelKey,
  withRotation,
  type KeyRotation,
  type MasterKeyStatus,
} from './masterKey';

const A = 'mk_3f9a0c41d27be865';
const B = 'mk_b81e2d07c4a95f13';
const C = 'mk_0123456789abcdef';

function rotation(over: Partial<KeyRotation> = {}): KeyRotation {
  return {
    id: 'rot_01JABCM8Q9R0S1T2V3V4W5X6Y7',
    status: 'running',
    fromKeyId: A,
    toKeyId: B,
    totalKeys: 200,
    rewrappedKeys: 0,
    startedAt: '2026-10-24T08:00:00Z',
    ...over,
  };
}

function status(over: Partial<MasterKeyStatus> = {}): MasterKeyStatus {
  return { activeKeyId: A, newKeyId: B, restartRequired: false, ...over };
}

function view(over: Partial<ErrorView> = {}): ErrorView {
  return {
    code: undefined,
    status: undefined,
    message: 'Server message',
    fields: {},
    attemptsRemaining: undefined,
    retryAfterSeconds: undefined,
    maxTransferBytes: undefined,
    files: undefined,
    ...over,
  };
}

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

describe('screenState', () => {
  it('asks for the new key when none is configured', () => {
    const { newKeyId: _omit, ...noNew } = status();
    expect(screenState(noNew, false)).toBe('noNewKey');
    expect(screenState({ ...noNew, latestRotation: rotation({ status: 'completed' }) }, false)).toBe(
      'noNewKey',
    );
    expect(screenState({ ...noNew, latestRotation: rotation({ status: 'failed' }) }, false)).toBe('noNewKey');
  });

  it('is ready with a new key and no rotation, or an older completed one', () => {
    expect(screenState(status(), false)).toBe('ready');
    expect(
      screenState(status({ latestRotation: rotation({ status: 'completed', toKeyId: C }) }), false),
    ).toBe('ready');
  });

  it('shows a running rotation between the configured keys, interrupted once stalled', () => {
    const s = status({ latestRotation: rotation() });
    expect(screenState(s, false)).toBe('running');
    expect(screenState(s, true)).toBe('interrupted');
  });

  it('shows a running rotation between other keys, stalled or not', () => {
    expect(screenState(status({ latestRotation: rotation({ toKeyId: C }) }), false)).toBe('otherRotation');
    expect(screenState(status({ latestRotation: rotation({ fromKeyId: C }) }), true)).toBe('otherRotation');
    const { newKeyId: _omit, ...noNew } = status();
    expect(screenState({ ...noNew, latestRotation: rotation() }, false)).toBe('otherRotation');
  });

  it('asks for the restart once the rotation to the new key completed', () => {
    const s = status({ restartRequired: true, latestRotation: rotation({ status: 'completed' }) });
    expect(screenState(s, false)).toBe('restartRequired');
    expect(screenState(s, true)).toBe('restartRequired');
  });

  it('shows a failed rotation with a new key', () => {
    expect(
      screenState(status({ latestRotation: rotation({ status: 'failed', error: 'boom' }) }), false),
    ).toBe('failed');
  });
});

describe('start availability', () => {
  it('offers the start in ready, failed and interrupted only', () => {
    expect(canStart('ready')).toBe(true);
    expect(canStart('failed')).toBe(true);
    expect(canStart('interrupted')).toBe(true);
    for (const k of ['noNewKey', 'running', 'otherRotation', 'restartRequired'] as const) {
      expect(canStart(k)).toBe(false);
    }
  });

  it('labels the button by state', () => {
    expect(startLabelKey('ready')).toBe('sysMasterKey.start.button');
    expect(startLabelKey('failed')).toBe('sysMasterKey.start.again');
    expect(startLabelKey('interrupted')).toBe('sysMasterKey.start.resume');
  });

  it('requires both checklist boxes', () => {
    expect(checklistDone(false, false)).toBe(false);
    expect(checklistDone(true, false)).toBe(false);
    expect(checklistDone(false, true)).toBe(false);
    expect(checklistDone(true, true)).toBe(true);
  });

  it('matches the configured keys', () => {
    expect(matchesConfiguredKeys(status(), rotation())).toBe(true);
    expect(matchesConfiguredKeys(status(), rotation({ toKeyId: C }))).toBe(false);
    const { newKeyId: _omit, ...noNew } = status();
    expect(matchesConfiguredKeys(noNew, rotation())).toBe(false);
  });
});

describe('polling decision', () => {
  it('polls only a running latest rotation', () => {
    expect(shouldPoll(undefined)).toBe(false);
    expect(shouldPoll(status())).toBe(false);
    expect(shouldPoll(status({ latestRotation: rotation() }))).toBe(true);
    expect(shouldPoll(status({ latestRotation: rotation({ status: 'completed' }) }))).toBe(false);
    expect(shouldPoll(status({ latestRotation: rotation({ status: 'failed' }) }))).toBe(false);
  });

  it('replaces the latest rotation', () => {
    const r = rotation({ rewrappedKeys: 5 });
    expect(withRotation(status(), r)).toEqual({ ...status(), latestRotation: r });
  });

  it('labels the rotation status, not by colour only', () => {
    expect(rotationStatusKey('running')).toBe('sysMasterKey.latest.statuses.running');
    expect(rotationStatusKey('completed')).toBe('sysMasterKey.latest.statuses.completed');
    expect(rotationStatusKey('failed')).toBe('sysMasterKey.latest.statuses.failed');
    expect(rotationStatusVariant('running')).toBe('info');
    expect(rotationStatusVariant('completed')).toBe('ok');
    expect(rotationStatusVariant('failed')).toBe('error');
  });
});

describe('progressView', () => {
  it('computes the percentage rounded down', () => {
    expect(progressView(rotation({ rewrappedKeys: 0 }))).toEqual({ percent: 0, done: 0, total: 200 });
    expect(progressView(rotation({ rewrappedKeys: 1 })).percent).toBe(0);
    expect(progressView(rotation({ rewrappedKeys: 199 })).percent).toBe(99);
    expect(progressView(rotation({ rewrappedKeys: 200 })).percent).toBe(100);
  });

  it('clamps to 100 % when more keys than counted were re-wrapped', () => {
    expect(progressView(rotation({ rewrappedKeys: 250 }))).toEqual({ percent: 100, done: 250, total: 200 });
  });

  it('is indeterminate without keys while running, full once completed', () => {
    expect(progressView(rotation({ totalKeys: 0, rewrappedKeys: 3 })).percent).toBeUndefined();
    expect(progressView(rotation({ totalKeys: 0, status: 'completed' })).percent).toBe(100);
    expect(progressView(rotation({ totalKeys: 0, status: 'failed' })).percent).toBeUndefined();
  });

  it('never goes negative', () => {
    expect(progressView(rotation({ totalKeys: -1, rewrappedKeys: -5 }))).toEqual({
      percent: undefined,
      done: 0,
      total: 0,
    });
  });

  it('writes the count text with formatted numbers', () => {
    const text = progressText({ percent: 50, done: 1000, total: 2000 }, t, (n) => `#${n}`);
    expect(text).toBe('sysMasterKey.progress.text {"done":"#1000","total":"#2000"}');
  });
});

describe('announcements', () => {
  it('finds the milestone reached', () => {
    expect(milestone(undefined)).toBe(0);
    expect(milestone(0)).toBe(0);
    expect(milestone(24)).toBe(0);
    expect(milestone(25)).toBe(25);
    expect(milestone(74)).toBe(50);
    expect(milestone(99)).toBe(75);
    expect(milestone(100)).toBe(100);
  });

  it('sets the baseline silently on the first read', () => {
    const step = announceProgress(undefined, rotation({ rewrappedKeys: 120 }));
    expect(step.message).toBeUndefined();
    expect(step.state).toEqual({ rotationId: rotation().id, milestone: 50, status: 'running' });
  });

  it('announces a start by the page, also for a resumed rotation', () => {
    expect(announceProgress(undefined, rotation(), true).message).toEqual({
      key: 'sysMasterKey.announce.started',
    });
    const previous = announceProgress(undefined, rotation({ rewrappedKeys: 60 })).state;
    const step = announceProgress(previous, rotation({ rewrappedKeys: 60 }), true);
    expect(step.message).toEqual({ key: 'sysMasterKey.announce.started' });
  });

  it('announces each milestone once, never on every read', () => {
    const counts = [10, 20, 50, 55, 60, 110, 120, 160, 199, 200, 210];
    let state = announceProgress(undefined, rotation({ rewrappedKeys: 0 })).state;
    const messages: unknown[] = [];
    for (const c of counts) {
      const step = announceProgress(state, rotation({ rewrappedKeys: c }));
      state = step.state;
      if (step.message !== undefined) {
        messages.push(step.message);
      }
    }
    expect(messages).toEqual([
      { key: 'sysMasterKey.announce.milestone', params: { percent: 25 } },
      { key: 'sysMasterKey.announce.milestone', params: { percent: 50 } },
      { key: 'sysMasterKey.announce.milestone', params: { percent: 75 } },
      { key: 'sysMasterKey.announce.milestone', params: { percent: 100 } },
    ]);
  });

  it('jumps straight to the highest milestone reached', () => {
    const state = announceProgress(undefined, rotation()).state;
    const step = announceProgress(state, rotation({ rewrappedKeys: 170 }));
    expect(step.message).toEqual({ key: 'sysMasterKey.announce.milestone', params: { percent: 75 } });
  });

  it('keeps the highest milestone announced when the percentage goes down', () => {
    const state = announceProgress(undefined, rotation({ rewrappedKeys: 120 })).state;
    const lower = announceProgress(state, rotation({ rewrappedKeys: 10, totalKeys: 200 }));
    expect(lower.message).toBeUndefined();
    expect(lower.state.milestone).toBe(50);
    expect(announceProgress(lower.state, rotation({ rewrappedKeys: 110 })).message).toBeUndefined();
  });

  it('announces the completion and the failure once', () => {
    const running = announceProgress(undefined, rotation({ rewrappedKeys: 200 })).state;
    const done = announceProgress(running, rotation({ rewrappedKeys: 200, status: 'completed' }));
    expect(done.message).toEqual({ key: 'sysMasterKey.announce.completed' });
    expect(
      announceProgress(done.state, rotation({ rewrappedKeys: 200, status: 'completed' })).message,
    ).toBeUndefined();
    const failed = announceProgress(running, rotation({ status: 'failed', error: 'x' }));
    expect(failed.message).toEqual({ key: 'sysMasterKey.announce.failed' });
    expect(announceProgress(failed.state, rotation({ status: 'failed' })).message).toBeUndefined();
  });

  it('starts again silently for another rotation', () => {
    const state = announceProgress(undefined, rotation({ rewrappedKeys: 200 })).state;
    const other = announceProgress(state, rotation({ id: 'rot_other', status: 'completed' }));
    expect(other.message).toBeUndefined();
    expect(other.state.rotationId).toBe('rot_other');
  });
});

describe('interruption detection', () => {
  it('needs both the time and the reads without progress', () => {
    let watch = observeProgress(undefined, rotation({ rewrappedKeys: 10 }), 0);
    expect(watch).toEqual({ rotationId: rotation().id, rewrappedKeys: 10, changedAt: 0, unchanged: 0 });
    expect(isStalled(watch, STALL_MS * 10)).toBe(false);
    for (let i = 1; i < STALL_READS; i++) {
      watch = observeProgress(watch, rotation({ rewrappedKeys: 10 }), i * 2_000);
    }
    expect(isStalled(watch, STALL_MS)).toBe(false);
    watch = observeProgress(watch, rotation({ rewrappedKeys: 10 }), STALL_READS * 2_000);
    expect(watch.unchanged).toBe(STALL_READS);
    expect(isStalled(watch, STALL_MS - 1)).toBe(false);
    expect(isStalled(watch, STALL_MS)).toBe(true);
  });

  it('resets when the counter moves or the rotation changes', () => {
    let watch = observeProgress(undefined, rotation({ rewrappedKeys: 10 }), 0);
    for (let i = 1; i <= 20; i++) {
      watch = observeProgress(watch, rotation({ rewrappedKeys: 10 }), i * 2_000);
    }
    expect(isStalled(watch, 40_000)).toBe(true);
    const moved = observeProgress(watch, rotation({ rewrappedKeys: 11 }), 42_000);
    expect(moved).toEqual({ rotationId: rotation().id, rewrappedKeys: 11, changedAt: 42_000, unchanged: 0 });
    expect(isStalled(moved, 42_000 + STALL_MS)).toBe(false);
    const other = observeProgress(watch, rotation({ id: 'rot_other', rewrappedKeys: 10 }), 50_000);
    expect(other.unchanged).toBe(0);
    expect(other.changedAt).toBe(50_000);
  });

  it('is not stalled without a watch', () => {
    expect(isStalled(undefined, 1e12)).toBe(false);
  });
});

describe('pollDelay', () => {
  it('reads every 2 s while visible, every 10 s hidden or stalled', () => {
    expect(pollDelay({ visible: true, stalled: false, errors: 0 })).toBe(POLL_MS);
    expect(pollDelay({ visible: false, stalled: false, errors: 0 })).toBe(SLOW_POLL_MS);
    expect(pollDelay({ visible: true, stalled: true, errors: 0 })).toBe(SLOW_POLL_MS);
  });

  it('backs off after failed reads, up to 30 s', () => {
    const delays = [1, 2, 3, 4, 5, 10].map((errors) => pollDelay({ visible: true, stalled: false, errors }));
    expect(delays).toEqual([4_000, 8_000, 16_000, MAX_BACKOFF_MS, MAX_BACKOFF_MS, MAX_BACKOFF_MS]);
    expect(pollDelay({ visible: false, stalled: false, errors: 1 })).toBe(SLOW_POLL_MS);
    expect(pollDelay({ visible: false, stalled: false, errors: 3 })).toBe(16_000);
  });

  it('retries network and server errors, stops on the others', () => {
    expect(pollErrorAction(view())).toBe('retry');
    expect(pollErrorAction(view({ status: 500 }))).toBe('retry');
    expect(pollErrorAction(view({ status: 503 }))).toBe('retry');
    expect(pollErrorAction(view({ status: 401, code: 'unauthenticated' }))).toBe('stop');
    expect(pollErrorAction(view({ status: 403, code: 'forbidden' }))).toBe('stop');
    expect(pollErrorAction(view({ status: 404, code: 'not-found' }))).toBe('stop');
  });
});

describe('pollHalted', () => {
  it('holds for its rotation only', () => {
    expect(pollHalted(undefined, 'rot_a')).toBe(false);
    expect(pollHalted({ reason: 'error', rotationId: 'rot_a' }, 'rot_a')).toBe(true);
    expect(pollHalted({ reason: 'idle', rotationId: 'rot_a' }, 'rot_a')).toBe(true);
    // Another rotation is polled again.
    expect(pollHalted({ reason: 'error', rotationId: 'rot_a' }, 'rot_b')).toBe(false);
  });

  it('halts the timer-driven reads once the admin is idle (fake clock)', () => {
    let clock = 0;
    const tracker = createActivityTracker({ subscribe: () => () => {} }, () => clock);
    expect(idleHalt(tracker, 'rot_a')).toBeUndefined();
    clock = IDLE_PAUSE_MS - 1;
    expect(idleHalt(tracker, 'rot_a')).toBeUndefined();
    clock = IDLE_PAUSE_MS;
    const halt = idleHalt(tracker, 'rot_a');
    expect(halt).toEqual({ reason: 'idle', rotationId: 'rot_a' });
    expect(pollHalted(halt, 'rot_a')).toBe(true);
    // "Resume updates" resets the idle clock.
    tracker.reset();
    expect(idleHalt(tracker, 'rot_a')).toBeUndefined();
  });
});

describe('code', () => {
  it('checks a TOTP code like the sign-in', () => {
    expect(codeError('totp', '')).toEqual({ key: 'fieldErrors.required' });
    expect(codeError('totp', '12345')).toEqual({ key: 'adminAuth.totp.format' });
    expect(codeError('totp', '12a456')).toEqual({ key: 'adminAuth.totp.format' });
    expect(codeError('totp', '123 456')).toBeUndefined();
  });

  it('checks a recovery code like the sign-in', () => {
    expect(codeError('recovery', '  ')).toEqual({ key: 'fieldErrors.required' });
    expect(codeError('recovery', 'x'.repeat(33))).toEqual({ key: 'fieldErrors.too-long' });
    expect(codeError('recovery', ' abcd-efgh ')).toBeUndefined();
  });

  it('builds the body with exactly one member', () => {
    expect(startBody('totp', ' 123 456 ')).toEqual({ code: '123456' });
    expect(startBody('recovery', ' abcd-efgh ')).toEqual({ recoveryCode: 'abcd-efgh' });
  });
});

describe('start errors', () => {
  const RUNNING = 'A master key rotation is already running.';
  const MISMATCH = 'A rotation between other keys is unfinished; finish or abandon it with the command line.';
  const RESTART =
    'The last rotation is complete; restart with the new key as TT_MASTER_KEY_FILE before starting another.';

  it('reads the detail of an API problem only', () => {
    expect(problemDetail(new ApiProblem(409, { code: 'state-conflict', detail: RUNNING } as never))).toBe(
      RUNNING,
    );
    expect(problemDetail(new ApiProblem(500, undefined))).toBeUndefined();
    expect(problemDetail(new Error('x'))).toBeUndefined();
  });

  it('classifies the 409 state-conflict by the server detail first', () => {
    expect(conflictKind(RUNNING, undefined)).toBe('running');
    expect(conflictKind(MISMATCH, undefined)).toBe('otherKeys');
    expect(conflictKind(RESTART, undefined)).toBe('restartRequired');
    // The detail wins over the status.
    expect(conflictKind(RUNNING, status({ restartRequired: true }))).toBe('running');
  });

  it('falls back to the status read after the refusal', () => {
    expect(conflictKind(undefined, undefined)).toBe('unknown');
    expect(conflictKind('Something else', status())).toBe('unknown');
    expect(conflictKind(undefined, status({ restartRequired: true }))).toBe('restartRequired');
    expect(conflictKind(undefined, status({ latestRotation: rotation() }))).toBe('running');
    expect(conflictKind(undefined, status({ latestRotation: rotation({ toKeyId: C }) }))).toBe('otherKeys');
  });

  it('words each conflict, with the server text or a generic message otherwise', () => {
    expect(conflictMessage('running', RUNNING)).toEqual({ key: 'sysMasterKey.errors.running' });
    expect(conflictMessage('otherKeys', undefined)).toEqual({ key: 'sysMasterKey.errors.otherKeys' });
    expect(conflictMessage('restartRequired', undefined)).toEqual({
      key: 'sysMasterKey.errors.restartRequired',
    });
    expect(conflictMessage('unknown', 'Odd state')).toEqual({ text: 'Odd state' });
    expect(conflictMessage('unknown', '')).toEqual({ key: 'errors.state-conflict' });
    expect(conflictMessage('unknown', undefined)).toEqual({ key: 'errors.state-conflict' });
  });

  it('keeps a wrong code in the dialog, with the attempts left', () => {
    expect(startFailure(view({ status: 401, code: 'invalid-credentials' }), undefined, undefined)).toEqual({
      kind: 'form',
      failure: { fields: { code: { key: 'adminAuth.totp.invalid' } } },
    });
    expect(
      startFailure(
        view({ status: 401, code: 'invalid-credentials', attemptsRemaining: 2 }),
        undefined,
        undefined,
      ),
    ).toEqual({
      kind: 'form',
      failure: { fields: { code: { key: 'adminAuth.totp.invalid' } }, attemptsRemaining: 2 },
    });
  });

  it('keeps a lock in the dialog, with its countdown', () => {
    expect(
      startFailure(view({ status: 429, code: 'rate-limited', retryAfterSeconds: 90 }), undefined, undefined),
    ).toEqual({
      kind: 'form',
      failure: {
        general: { key: 'adminAuth.totp.locked', params: { count: 90 } },
        fields: {},
        retryAfterSeconds: 90,
      },
    });
    expect(startFailure(view({ status: 429, code: 'rate-limited' }), undefined, undefined)).toEqual({
      kind: 'form',
      failure: { general: { key: 'adminAuth.login.lockedNoDelay' }, fields: {} },
    });
  });

  it('keeps a malformed code in the dialog', () => {
    expect(startFailure(view({ status: 400, code: 'validation-failed' }), undefined, undefined)).toEqual({
      kind: 'form',
      failure: { fields: { code: { key: 'adminAuth.totp.format' } } },
    });
  });

  it('closes the dialog on a missing new key and reads the status again', () => {
    expect(startFailure(view({ status: 409, code: 'new-master-key-missing' }), undefined, undefined)).toEqual(
      {
        kind: 'page',
        message: { key: 'sysMasterKey.errors.newKeyMissing' },
        reload: true,
      },
    );
  });

  it('closes the dialog on each state conflict', () => {
    const conflict = view({ status: 409, code: 'state-conflict' });
    expect(startFailure(conflict, RUNNING, status())).toEqual({
      kind: 'page',
      message: { key: 'sysMasterKey.errors.running' },
      reload: true,
    });
    expect(startFailure(conflict, MISMATCH, undefined)).toMatchObject({
      message: { key: 'sysMasterKey.errors.otherKeys' },
    });
    expect(startFailure(conflict, RESTART, undefined)).toMatchObject({
      message: { key: 'sysMasterKey.errors.restartRequired' },
    });
    expect(startFailure(conflict, undefined, status({ restartRequired: true }))).toMatchObject({
      message: { key: 'sysMasterKey.errors.restartRequired' },
    });
    expect(startFailure(conflict, 'New case', status())).toMatchObject({ message: { text: 'New case' } });
  });

  it('shows forbidden and an ended session on the page', () => {
    expect(
      startFailure(view({ status: 403, code: 'forbidden', message: 'Forbidden.' }), undefined, undefined),
    ).toEqual({
      kind: 'page',
      message: { text: 'Forbidden.' },
      reload: false,
    });
    expect(
      startFailure(
        view({ status: 401, code: 'unauthenticated', message: 'Signed out.' }),
        undefined,
        undefined,
      ),
    ).toEqual({ kind: 'page', message: { text: 'Signed out.' }, reload: false });
  });

  it('keeps network and server errors in the dialog', () => {
    expect(startFailure(view({ message: 'Network error.' }), undefined, undefined)).toEqual({
      kind: 'form',
      failure: { general: { text: 'Network error.' }, fields: {} },
    });
    expect(
      startFailure(view({ status: 500, code: 'internal', message: 'Oops.' }), undefined, undefined),
    ).toEqual({
      kind: 'form',
      failure: { general: { text: 'Oops.' }, fields: {} },
    });
  });
});
