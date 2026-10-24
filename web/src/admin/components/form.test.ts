import { describe, expect, it, vi } from 'vitest';
import {
  beforeUnloadWarning,
  errorFor,
  focusById,
  normalizeOutcome,
  summaryFromFields,
  unsavedChangesGuard,
  type BeforeUnloadLike,
} from './form';

describe('normalizeOutcome', () => {
  it('treats void as a success with the default message', () => {
    expect(normalizeOutcome(undefined)).toEqual({ ok: true, message: undefined, errors: [] });
  });

  it('keeps the message of a success', () => {
    expect(normalizeOutcome({ ok: true, message: 'Done' })).toEqual({
      ok: true,
      message: 'Done',
      errors: [],
    });
  });

  it('copies the errors of a failure', () => {
    const errors = [{ id: 'a', label: 'A', message: 'bad' }];
    const out = normalizeOutcome({ ok: false, message: 'Failed', errors });
    expect(out).toEqual({ ok: false, message: 'Failed', errors });
    expect(out.errors).not.toBe(errors);
  });

  it('gives an empty error list to a failure without errors', () => {
    expect(normalizeOutcome({ ok: false })).toEqual({ ok: false, message: undefined, errors: [] });
  });
});

describe('summaryFromFields', () => {
  const fields = {
    name: { id: 'f-name', label: 'Name' },
    internalCidrs: { id: 'f-cidrs', label: 'Ranges' },
    'message.fr': { id: 'f-msg-fr', label: 'Message (fr)' },
  };

  it('lists errors in the order of the form, matching parent paths, once per field', () => {
    const out = summaryFromFields(
      {
        'internalCidrs.2': { code: 'invalid-cidr', message: 'Invalid range' },
        'internalCidrs.4': { code: 'invalid-cidr', message: 'Other' },
        name: { code: 'required', message: 'Required' },
        'message.fr.body': { code: 'too-long', message: 'Too long' },
      },
      fields,
    );
    expect(out.errors).toEqual([
      { id: 'f-name', label: 'Name', message: 'Required' },
      { id: 'f-cidrs', label: 'Ranges', message: 'Invalid range' },
      { id: 'f-msg-fr', label: 'Message (fr)', message: 'Too long' },
    ]);
    expect(out.unmatched).toEqual([]);
  });

  it('returns the unknown fields apart', () => {
    const out = summaryFromFields({ fqdn: { code: 'invalid', message: 'Invalid' } }, fields);
    expect(out.errors).toEqual([]);
    expect(out.unmatched).toEqual(['fqdn']);
  });
});

describe('errorFor', () => {
  it('finds the message of an element id', () => {
    const errors = [{ id: 'a', label: 'A', message: 'bad' }];
    expect(errorFor(errors, 'a')).toBe('bad');
    expect(errorFor(errors, 'b')).toBeUndefined();
  });
});

describe('unsavedChangesGuard', () => {
  it('lets a clean form leave without asking', () => {
    const confirm = vi.fn(() => false);
    expect(unsavedChangesGuard(() => false, confirm, 'leave?')('/x')).toBe(true);
    expect(confirm).not.toHaveBeenCalled();
  });

  it('asks before leaving a dirty form', () => {
    const confirm = vi.fn(() => false);
    const guard = unsavedChangesGuard(() => true, confirm, 'leave?');
    expect(guard('/x')).toBe(false);
    expect(confirm).toHaveBeenCalledWith('leave?');
    confirm.mockReturnValue(true);
    expect(guard('/x')).toBe(true);
  });
});

describe('beforeUnloadWarning', () => {
  function event(): BeforeUnloadLike & { prevented: boolean } {
    const e = {
      prevented: false,
      returnValue: undefined as unknown,
      preventDefault() {
        e.prevented = true;
      },
    };
    return e;
  }

  it('warns only while dirty', () => {
    let dirty = false;
    const listener = beforeUnloadWarning(() => dirty);
    const clean = event();
    listener(clean);
    expect(clean.prevented).toBe(false);
    expect(clean.returnValue).toBeUndefined();
    dirty = true;
    const e = event();
    listener(e);
    expect(e.prevented).toBe(true);
    expect(e.returnValue).toBe('');
  });
});

describe('focusById', () => {
  it('focuses an existing element', () => {
    const focus = vi.fn();
    expect(focusById({ getElementById: (id) => (id === 'a' ? { focus } : null) }, 'a')).toBe(true);
    expect(focus).toHaveBeenCalled();
  });

  it('reports a missing element', () => {
    expect(focusById({ getElementById: () => null }, 'a')).toBe(false);
  });
});
