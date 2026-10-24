import { describe, expect, it } from 'vitest';
import type { ErrorView } from '../../../shared/api/problem';
import en from '../../../locales/en/sysMaintenance.json';
import fr from '../../../locales/fr/sysMaintenance.json';
import {
  MAX_MESSAGE_LENGTH,
  buildMaintenanceUpdate,
  confirmationFor,
  confirmationKeys,
  formFromMaintenance,
  isForbiddenCodePoint,
  isMaintenanceDirty,
  maintenanceFailure,
  maintenanceView,
  messageIssue,
  messageIssueText,
  messageLength,
  savedKey,
  validateMaintenanceForm,
  type Maintenance,
  type MaintenanceFieldRefs,
} from './maintenance';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

const refs: MaintenanceFieldRefs = {
  enabled: { id: 'enabled', label: 'Enabled' },
  fr: { id: 'fr', label: 'French' },
  en: { id: 'en', label: 'English' },
};

const off: Maintenance = { enabled: false, source: 'none', adminEnabled: false };
const onAdmin: Maintenance = {
  enabled: true,
  source: 'admin',
  adminEnabled: true,
  since: '2026-10-24T08:00:00Z',
  message: { fr: 'Bonjour', en: 'Hello' },
};
const forcedOff: Maintenance = {
  enabled: true,
  source: 'environment',
  adminEnabled: false,
  since: '2026-10-24T08:00:00Z',
};
const forcedOn: Maintenance = { ...forcedOff, adminEnabled: true };

function view(partial: Partial<ErrorView>): ErrorView {
  return {
    code: undefined,
    status: undefined,
    message: 'general',
    fields: {},
    attemptsRemaining: undefined,
    retryAfterSeconds: undefined,
    maxTransferBytes: undefined,
    ...partial,
  } as ErrorView;
}

/** Looks a dotted key up in a bundle. */
function lookup(bundle: unknown, key: string): unknown {
  return key
    .split('.')
    .reduce<unknown>((node, part) => (node as Record<string, unknown> | undefined)?.[part], bundle);
}

function expectKey(key: string): void {
  const [area, ...rest] = key.split('.');
  expect(area).toBe('sysMaintenance');
  for (const bundle of [en, fr]) {
    expect(typeof lookup(bundle, rest.join('.')), key).toBe('string');
  }
}

describe('message check', () => {
  it('counts code points, not UTF-16 units', () => {
    expect(messageIssue('😀'.repeat(MAX_MESSAGE_LENGTH))).toBeUndefined();
    expect(messageIssue('😀'.repeat(MAX_MESSAGE_LENGTH + 1))).toBe('too-long');
  });

  it('refuses control characters except line feed, separators and bidi controls', () => {
    expect(isForbiddenCodePoint(0x0a)).toBe(false);
    for (const cp of [0x00, 0x09, 0x0d, 0x1f, 0x7f, 0x85, 0x9f, 0x2028, 0x2029, 0x061c, 0x200e, 0x200f]) {
      expect(isForbiddenCodePoint(cp), cp.toString(16)).toBe(true);
    }
    for (const cp of [0x202a, 0x202e, 0x2066, 0x2069]) {
      expect(isForbiddenCodePoint(cp), cp.toString(16)).toBe(true);
    }
    for (const cp of [0x20, 0x41, 0xa0, 0xe9, 0x200b, 0x2027, 0x202f, 0x2065, 0x206a, 0x1f600]) {
      expect(isForbiddenCodePoint(cp), cp.toString(16)).toBe(false);
    }
  });

  it('accepts empty messages, line feeds and exactly 500 code points', () => {
    expect(messageIssue('')).toBeUndefined();
    expect(messageIssue('   ')).toBeUndefined();
    expect(messageIssue('Line 1\nLine 2')).toBeUndefined();
    expect(messageIssue('😀'.repeat(MAX_MESSAGE_LENGTH))).toBeUndefined();
    expect(messageIssue(`  ${'a'.repeat(MAX_MESSAGE_LENGTH)}  `)).toBeUndefined();
  });

  it('reports too long and forbidden characters', () => {
    expect(messageIssue('a'.repeat(MAX_MESSAGE_LENGTH + 1))).toBe('too-long');
    expect(messageIssue('a\tb')).toBe('forbidden-character');
    expect(messageIssue('a\r\nb')).toBe('forbidden-character');
    expect(messageIssue('a b')).toBe('forbidden-character');
    expect(messageIssue('a‮b')).toBe('forbidden-character');
    expect(messageIssue(`${'a'.repeat(MAX_MESSAGE_LENGTH + 1)}\u0007`)).toBe('forbidden-character');
  });

  it('translates the issues', () => {
    expect(messageIssueText('too-long', t)).toBe('sysMaintenance.errors.tooLong {"max":500}');
    expect(messageIssueText('forbidden-character', t)).toBe('sysMaintenance.errors.forbiddenCharacter');
  });
});

describe('messageLength', () => {
  it('counts code points of the normalised message', () => {
    expect(messageLength('  abc  ')).toBe(3);
    expect(messageLength('\u{1F600}é')).toBe(2);
    expect(messageLength('')).toBe(0);
  });
});

describe('maintenanceView', () => {
  it('describes the mode off', () => {
    expect(maintenanceView(off)).toEqual({
      enabled: false,
      variant: 'ok',
      stateKey: 'sysMaintenance.state.off',
      sourceKey: 'sysMaintenance.source.none',
      since: undefined,
      forced: false,
      storedKey: undefined,
    });
  });

  it('describes the mode on by the admin', () => {
    const v = maintenanceView(onAdmin);
    expect(v).toMatchObject({ enabled: true, variant: 'warning', forced: false, storedKey: undefined });
    expect(v.since).toBe('2026-10-24T08:00:00Z');
    expect(v.sourceKey).toBe('sysMaintenance.source.admin');
  });

  it('describes the mode forced by the environment with the stored choice', () => {
    expect(maintenanceView(forcedOff)).toMatchObject({
      forced: true,
      sourceKey: 'sysMaintenance.source.environment',
      storedKey: 'sysMaintenance.stored.off',
    });
    expect(maintenanceView(forcedOn).storedKey).toBe('sysMaintenance.stored.on');
  });

  it('ignores an invalid or irrelevant start date', () => {
    expect(maintenanceView({ ...onAdmin, since: 'not a date' }).since).toBeUndefined();
    expect(maintenanceView({ ...off, since: '2026-10-24T08:00:00Z' }).since).toBeUndefined();
  });

  it('uses keys present in both languages', () => {
    for (const state of [off, onAdmin, forcedOff, forcedOn]) {
      const v = maintenanceView(state);
      expectKey(v.stateKey);
      expectKey(v.sourceKey);
      if (v.storedKey !== undefined) {
        expectKey(v.storedKey);
      }
    }
  });
});

describe('form model', () => {
  it('fills the form from the state', () => {
    expect(formFromMaintenance(off)).toEqual({ enabled: false, messages: { fr: '', en: '' } });
    expect(formFromMaintenance(onAdmin)).toEqual({ enabled: true, messages: { fr: 'Bonjour', en: 'Hello' } });
    expect(formFromMaintenance(forcedOff).enabled).toBe(true);
  });

  it('tracks changes, ignoring surrounding white space', () => {
    const form = formFromMaintenance(onAdmin);
    expect(isMaintenanceDirty(onAdmin, form)).toBe(false);
    expect(isMaintenanceDirty(onAdmin, { ...form, messages: { ...form.messages, fr: ' Bonjour\n' } })).toBe(
      false,
    );
    expect(isMaintenanceDirty(onAdmin, { ...form, messages: { ...form.messages, en: 'Hi' } })).toBe(true);
    expect(isMaintenanceDirty(onAdmin, { ...form, enabled: false })).toBe(true);
  });
});

describe('buildMaintenanceUpdate', () => {
  it('sends the non-empty messages, trimmed', () => {
    expect(
      buildMaintenanceUpdate({ enabled: true, messages: { fr: ' Bonjour\nà tous ', en: '' } }, false),
    ).toEqual({
      enabled: true,
      message: { fr: 'Bonjour\nà tous' },
    });
    expect(buildMaintenanceUpdate({ enabled: false, messages: { fr: 'a', en: 'b' } }, false)).toEqual({
      enabled: false,
      message: { fr: 'a', en: 'b' },
    });
  });

  it('omits the message when every field is empty (clears the stored messages)', () => {
    const body = buildMaintenanceUpdate({ enabled: false, messages: { fr: ' ', en: '' } }, false);
    expect(body).toEqual({ enabled: false });
    expect('message' in body).toBe(false);
  });

  it('always sends enabled true while the environment forces the mode', () => {
    expect(buildMaintenanceUpdate({ enabled: false, messages: { fr: '', en: '' } }, true)).toEqual({
      enabled: true,
    });
  });
});

describe('confirmation', () => {
  it('asks before enabling or disabling', () => {
    expect(confirmationFor(off, { enabled: true, messages: { fr: '', en: '' } })).toBe('enable');
    expect(confirmationFor(onAdmin, { enabled: false, messages: { fr: '', en: '' } })).toBe('disable');
  });

  it('does not ask when only the messages change', () => {
    expect(confirmationFor(onAdmin, { enabled: true, messages: { fr: 'x', en: '' } })).toBeUndefined();
    expect(confirmationFor(off, { enabled: false, messages: { fr: 'x', en: '' } })).toBeUndefined();
  });

  it('asks while forced when the stored choice is still off', () => {
    expect(confirmationFor(forcedOff, formFromMaintenance(forcedOff))).toBe('keepAfterEnvironment');
    expect(confirmationFor(forcedOn, formFromMaintenance(forcedOn))).toBeUndefined();
  });

  it('uses keys present in both languages', () => {
    for (const kind of ['enable', 'disable', 'keepAfterEnvironment'] as const) {
      const keys = confirmationKeys(kind);
      expectKey(keys.title);
      expectKey(keys.text);
      expectKey(keys.action);
    }
  });

  it('chooses the saved message', () => {
    expect(savedKey(off, onAdmin)).toBe('sysMaintenance.saved.enabled');
    expect(savedKey(onAdmin, off)).toBe('sysMaintenance.saved.disabled');
    expect(savedKey(onAdmin, onAdmin)).toBe('sysMaintenance.saved.updated');
    for (const key of [
      'sysMaintenance.saved.enabled',
      'sysMaintenance.saved.disabled',
      'sysMaintenance.saved.updated',
    ]) {
      expectKey(key);
    }
  });
});

describe('validation and errors', () => {
  it('validates every message', () => {
    expect(validateMaintenanceForm({ enabled: true, messages: { fr: '', en: 'ok' } }, refs, t)).toEqual([]);
    expect(
      validateMaintenanceForm({ enabled: true, messages: { fr: 'a‮b', en: 'x'.repeat(501) } }, refs, t),
    ).toEqual([
      { id: 'fr', label: 'French', message: 'sysMaintenance.errors.forbiddenCharacter' },
      { id: 'en', label: 'English', message: 'sysMaintenance.errors.tooLong {"max":500}' },
    ]);
  });

  it('maps the 409 of a forced mode', () => {
    expect(maintenanceFailure(view({ status: 409, code: 'state-conflict' }), refs, t)).toEqual({
      ok: false,
      message: 'sysMaintenance.errors.forced',
    });
  });

  it('maps an invalid message to its field', () => {
    const out = maintenanceFailure(
      view({
        status: 400,
        code: 'validation-failed',
        fields: { 'message.fr': { code: 'invalid-format', message: 'bad' } },
      }),
      refs,
      t,
    );
    expect(out).toEqual({
      ok: false,
      errors: [{ id: 'fr', label: 'French', message: 'sysMaintenance.errors.invalidMessage {"max":500}' }],
    });
  });

  it('keeps the general message for an unknown field', () => {
    const out = maintenanceFailure(
      view({
        status: 400,
        code: 'validation-failed',
        fields: { message: { code: 'invalid-format', message: 'bad' } },
      }),
      refs,
      t,
    );
    expect(out).toEqual({ ok: false, message: 'general', errors: [] });
  });

  it('shows any other error as a general message', () => {
    expect(maintenanceFailure(view({ status: 403, code: 'forbidden' }), refs, t)).toEqual({
      ok: false,
      message: 'general',
    });
  });
});
