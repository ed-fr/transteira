import { describe, expect, it, vi } from 'vitest';
import en from '../../locales/en/adminComponents.json';
import fr from '../../locales/fr/adminComponents.json';
import {
  canDismissSecret,
  copiedAfter,
  secretCancelGuard,
  secretLeaveMessage,
  secretPending,
} from './secretOnce';

describe('canDismissSecret', () => {
  it('requires the acknowledgement or a copy', () => {
    expect(canDismissSecret(false, false)).toBe(false);
    expect(canDismissSecret(true, false)).toBe(true);
    expect(canDismissSecret(false, true)).toBe(true);
  });
});

describe('copiedAfter', () => {
  it('counts only a successful copy, and keeps it', () => {
    expect(copiedAfter(false, true)).toBe(true);
    expect(copiedAfter(true, false)).toBe(true);
    expect(copiedAfter(false, false)).toBe(false);
  });

  it('leaves the dialog non-dismissable and pending after a failed copy', () => {
    const copied = copiedAfter(false, false);
    expect(canDismissSecret(false, copied)).toBe(false);
    expect(secretPending('tt_abc', false, copied)).toBe(true);
    let pending = secretPending('tt_abc', false, copied);
    const guard = secretCancelGuard(() => pending);
    const event = { preventDefault: vi.fn() };
    guard(event);
    expect(event.preventDefault).toHaveBeenCalledTimes(1);
    // A later successful copy makes it dismissable.
    pending = secretPending('tt_abc', false, copiedAfter(copied, true));
    expect(pending).toBe(false);
  });
});

describe('secretPending', () => {
  it('is pending while a secret is shown and not dismissable', () => {
    expect(secretPending('tt_abc', false, false)).toBe(true);
    expect(secretPending('tt_abc', true, false)).toBe(false);
    expect(secretPending('tt_abc', false, true)).toBe(false);
    expect(secretPending('', false, false)).toBe(false);
  });
});

describe('secretCancelGuard', () => {
  it('refuses the cancel only while pending', () => {
    let pending = true;
    const guard = secretCancelGuard(() => pending);
    const event = { preventDefault: vi.fn() };
    guard(event);
    expect(event.preventDefault).toHaveBeenCalledTimes(1);
    pending = false;
    guard(event);
    expect(event.preventDefault).toHaveBeenCalledTimes(1);
  });
});

describe('secretLeaveMessage', () => {
  it('joins the title and the text, never the secret', () => {
    expect(secretLeaveMessage((k) => k)).toBe(
      'adminComponents.secretOnce.leaveConfirm.title\n\nadminComponents.secretOnce.leaveConfirm.text',
    );
  });

  it('has the messages in every language', () => {
    for (const bundle of [en, fr]) {
      for (const key of [
        'text',
        'shownOnce',
        'label',
        'copy',
        'acknowledge',
        'close',
        'closeDisabled',
      ] as const) {
        expect(bundle.secretOnce[key]).toBeTruthy();
      }
      expect(bundle.secretOnce.leaveConfirm.title).toBeTruthy();
      expect(bundle.secretOnce.leaveConfirm.text).toBeTruthy();
    }
  });
});
