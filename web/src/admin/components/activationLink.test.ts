import { describe, expect, it, vi } from 'vitest';
import {
  activationBeforeUnload,
  activationLeaveGuard,
  expiryText,
  leaveMessage,
  type BeforeUnloadLike,
} from './activationLink';

describe('activationLeaveGuard', () => {
  it('lets the navigation through once acknowledged', () => {
    const confirm = vi.fn(() => false);
    expect(activationLeaveGuard(() => false, confirm, 'msg')('/admins')).toBe(true);
    expect(confirm).not.toHaveBeenCalled();
  });

  it('asks for a confirmation while pending', () => {
    const confirm = vi.fn((_message: string) => false);
    const guard = activationLeaveGuard(() => true, confirm, 'msg');
    expect(guard('/admins')).toBe(false);
    expect(confirm).toHaveBeenCalledWith('msg');
    confirm.mockReturnValue(true);
    expect(guard('/admins')).toBe(true);
  });

  it('reads the pending state at navigation time', () => {
    let pending = true;
    const guard = activationLeaveGuard(
      () => pending,
      () => false,
      'msg',
    );
    expect(guard('/')).toBe(false);
    pending = false;
    expect(guard('/')).toBe(true);
  });
});

describe('leaveMessage', () => {
  it('joins the title and the explanation', () => {
    expect(leaveMessage((key) => `[${key}]`)).toBe(
      '[adminAccounts.activationLink.leaveConfirm.title]\n\n[adminAccounts.activationLink.leaveConfirm.text]',
    );
  });
});

describe('activationBeforeUnload', () => {
  it('warns while pending', () => {
    const event: BeforeUnloadLike = { preventDefault: vi.fn() };
    activationBeforeUnload(() => true)(event);
    expect(event.preventDefault).toHaveBeenCalled();
    expect(event.returnValue).toBe('');
  });

  it('does nothing once acknowledged', () => {
    const event: BeforeUnloadLike = { preventDefault: vi.fn() };
    activationBeforeUnload(() => false)(event);
    expect(event.preventDefault).not.toHaveBeenCalled();
    expect(event.returnValue).toBeUndefined();
  });
});

describe('expiryText', () => {
  const t = (key: string, params: Record<string, string>): string => `${key}:${params['date']}`;

  it('formats a valid date', () => {
    expect(expiryText('2026-10-22T16:25:00Z', (d) => d.toISOString(), t)).toBe(
      'adminAccounts.activationLink.expires:2026-10-22T16:25:00.000Z',
    );
  });

  it('returns undefined for an invalid date', () => {
    expect(expiryText('not a date', () => 'x', t)).toBeUndefined();
  });
});
