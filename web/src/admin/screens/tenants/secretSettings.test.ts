import { describe, expect, it } from 'vitest';
import {
  MAX_FILE_MIB,
  MIB,
  MIN_FILE_MIB,
  SECRET_DURATIONS,
  bytesToMibText,
  parseFileMib,
  secretDraftChanged,
  secretSettingsBody,
  sortDurations,
  toDraft,
  toggleDuration,
  validateSecretSettings,
  type SecretSettings,
} from './secretSettings';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

const fields = {
  durations: { id: 'd', label: 'Durations' },
  defaultDuration: { id: 'def', label: 'Default' },
  fileMaxBytes: { id: 'f', label: 'File' },
};

const saved: SecretSettings = {
  enabled: true,
  durations: ['7d', '1h', '1d'],
  defaultDuration: '1d',
  fileAllowed: true,
  fileMaxBytes: 10 * MIB,
  emailAllowed: true,
};

describe('catalogue and file size', () => {
  it('orders a selection like the catalogue and drops unknown values', () => {
    expect(sortDurations(['7d', 'x', '1h', '1h'])).toEqual(['1h', '7d']);
    expect(SECRET_DURATIONS).toEqual(['1h', '12h', '1d', '3d', '7d', '30d']);
  });

  it('parses a size in MiB between 1 and 25', () => {
    expect(parseFileMib('10')).toBe(10 * MIB);
    expect(parseFileMib(' 1,5 ')).toBe(1.5 * MIB);
    expect(parseFileMib(String(MIN_FILE_MIB))).toBe(MIB);
    expect(parseFileMib(String(MAX_FILE_MIB))).toBe(25 * MIB);
    for (const bad of ['', '0', '0.9', '26', '25.001', 'abc', '-3', '1e1', '1.2345']) {
      expect(parseFileMib(bad), bad).toBeUndefined();
    }
  });

  it('writes a size in bytes as MiB text', () => {
    expect(bytesToMibText(10 * MIB)).toBe('10');
    expect(bytesToMibText(1.5 * MIB)).toBe('1.5');
  });
});

describe('draft', () => {
  it('reads the saved settings', () => {
    expect(toDraft(saved)).toEqual({
      enabled: true,
      durations: ['1h', '1d', '7d'],
      defaultDuration: '1d',
      fileAllowed: true,
      fileMibText: '10',
      emailAllowed: true,
      emailRequiresPassphrase: false,
    });
  });

  it('takes the first duration when no default is saved', () => {
    const { defaultDuration: _drop, ...rest } = saved;
    expect(toDraft(rest).defaultDuration).toBe('1h');
    expect(toDraft({ ...rest, durations: [] }).defaultDuration).toBe('');
  });

  it('keeps the default duration while it is offered and moves it otherwise', () => {
    const draft = toDraft(saved);
    expect(toggleDuration(draft, '3d', true)).toEqual({
      durations: ['1h', '1d', '3d', '7d'],
      defaultDuration: '1d',
    });
    expect(toggleDuration(draft, '1d', false)).toEqual({ durations: ['1h', '7d'], defaultDuration: '1h' });
    expect(toggleDuration({ durations: ['1h'], defaultDuration: '1h' }, '1h', false)).toEqual({
      durations: [],
      defaultDuration: '',
    });
    expect(toggleDuration({ durations: [], defaultDuration: '' }, '7d', true)).toEqual({
      durations: ['7d'],
      defaultDuration: '7d',
    });
  });
});

describe('validation', () => {
  it('accepts a valid draft', () => {
    expect(validateSecretSettings(toDraft(saved), fields, t)).toEqual([]);
  });

  it('requires a duration', () => {
    const out = validateSecretSettings({ ...toDraft(saved), durations: [], defaultDuration: '' }, fields, t);
    expect(out.map((e) => e.id)).toEqual(['d']);
  });

  it('requires a default among the offered durations', () => {
    const out = validateSecretSettings({ ...toDraft(saved), defaultDuration: '30d' }, fields, t);
    expect(out.map((e) => e.id)).toEqual(['def']);
    expect(
      validateSecretSettings({ ...toDraft(saved), defaultDuration: '' }, fields, t).map((e) => e.id),
    ).toEqual(['def']);
  });

  it('refuses an invalid file size', () => {
    const out = validateSecretSettings({ ...toDraft(saved), fileMibText: '30' }, fields, t);
    expect(out).toEqual([
      { id: 'f', label: 'File', message: 'adminSecrets.settings.errors.fileSize {"min":1,"max":25}' },
    ]);
  });
});

describe('body and dirty state', () => {
  it('builds the body that replaces every setting', () => {
    expect(secretSettingsBody(toDraft(saved))).toEqual({
      enabled: true,
      durations: ['1h', '1d', '7d'],
      defaultDuration: '1d',
      fileAllowed: true,
      fileMaxBytes: 10 * MIB,
      emailAllowed: true,
      emailRequiresPassphrase: false,
    });
  });

  it('sends the passphrase rule only with e-mail delivery, and no empty default', () => {
    const draft = { ...toDraft(saved), emailRequiresPassphrase: true };
    expect(secretSettingsBody(draft).emailRequiresPassphrase).toBe(true);
    expect(secretSettingsBody({ ...draft, emailAllowed: false }).emailRequiresPassphrase).toBe(false);
    expect('defaultDuration' in secretSettingsBody({ ...draft, defaultDuration: '' })).toBe(false);
  });

  it('falls back to 10 MiB for an invalid size (validate first)', () => {
    expect(secretSettingsBody({ ...toDraft(saved), fileMibText: 'x' }).fileMaxBytes).toBe(10 * MIB);
  });

  it('detects every change', () => {
    const base = toDraft(saved);
    expect(secretDraftChanged(base, { ...base })).toBe(false);
    expect(secretDraftChanged(base, { ...base, fileMibText: ' 10 ' })).toBe(false);
    const changes = [
      { enabled: false },
      { durations: ['1h' as const] },
      { defaultDuration: '7d' as const },
      { fileAllowed: false },
      { fileMibText: '12' },
      { emailAllowed: false },
      { emailRequiresPassphrase: true },
    ];
    for (const change of changes) {
      expect(secretDraftChanged(base, { ...base, ...change }), JSON.stringify(change)).toBe(true);
    }
  });
});
