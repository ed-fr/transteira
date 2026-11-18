import { describe, expect, it } from 'vitest';
import {
  EXPRESS_LIMITS,
  MAX_FILE_MIB,
  MIB,
  MIN_FILE_MIB,
  SECRET_DURATIONS,
  bytesToMibText,
  parseBoundedInt,
  parseFileMib,
  purgeResultText,
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
  expressPerHourPerIp: { id: 'xi', label: 'Per IP' },
  expressPerHourPerToken: { id: 'xt', label: 'Per token' },
  expressMaxPending: { id: 'xp', label: 'Pending' },
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
      expressEnabled: false,
      expressPerHourPerIpText: '10',
      expressPerHourPerTokenText: '100',
      expressMaxPendingText: '1000',
    });
  });

  it('reads the express settings of a 2.3 server', () => {
    const draft = toDraft({
      ...saved,
      expressEnabled: true,
      expressPerHourPerIp: 5,
      expressPerHourPerToken: 50,
      expressMaxPending: 200,
    });
    expect(draft).toMatchObject({
      expressEnabled: true,
      expressPerHourPerIpText: '5',
      expressPerHourPerTokenText: '50',
      expressMaxPendingText: '200',
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

describe('bounded integers', () => {
  it('parses digits within the bounds only', () => {
    expect(parseBoundedInt(' 10 ', 1, 1000)).toBe(10);
    expect(parseBoundedInt('1000', 1, 1000)).toBe(1000);
    for (const bad of ['', '0', '1001', '1.5', '-2', 'abc', '1e2', '1234567890']) {
      expect(parseBoundedInt(bad, 1, 1000), bad).toBeUndefined();
    }
  });

  it('documents the limits', () => {
    expect(EXPRESS_LIMITS.perHourPerIp).toEqual({ min: 1, max: 1000, def: 10 });
    expect(EXPRESS_LIMITS.perHourPerToken).toEqual({ min: 1, max: 10000, def: 100 });
    expect(EXPRESS_LIMITS.maxPending).toEqual({ min: 1, max: 100000, def: 1000 });
  });
});

describe('purge', () => {
  it('words the number of deleted secrets', () => {
    expect(purgeResultText(412, t)).toBe('adminSecrets.express.purge.done {"count":412}');
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

describe('express limits validation', () => {
  it('refuses each limit out of its bounds, with its own field', () => {
    const base = toDraft(saved);
    const out = validateSecretSettings(
      {
        ...base,
        expressPerHourPerIpText: '0',
        expressPerHourPerTokenText: '10001',
        expressMaxPendingText: 'x',
      },
      fields,
      t,
    );
    expect(out.map((e) => e.id)).toEqual(['xi', 'xt', 'xp']);
    expect(out[1]?.message).toBe('adminSecrets.settings.errors.expressLimit {"min":1,"max":10000}');
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
      expressEnabled: false,
      expressPerHourPerIp: 10,
      expressPerHourPerToken: 100,
      expressMaxPending: 1000,
    });
  });

  it('sends the express settings typed, and the defaults for an invalid text', () => {
    const draft = {
      ...toDraft(saved),
      expressEnabled: true,
      expressPerHourPerIpText: '3',
      expressPerHourPerTokenText: '40',
      expressMaxPendingText: '500',
    };
    expect(secretSettingsBody(draft)).toMatchObject({
      expressEnabled: true,
      expressPerHourPerIp: 3,
      expressPerHourPerToken: 40,
      expressMaxPending: 500,
    });
    expect(
      secretSettingsBody({
        ...draft,
        expressPerHourPerIpText: 'x',
        expressPerHourPerTokenText: 'x',
        expressMaxPendingText: 'x',
      }),
    ).toMatchObject({ expressPerHourPerIp: 10, expressPerHourPerToken: 100, expressMaxPending: 1000 });
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
    expect(secretDraftChanged(base, { ...base, expressMaxPendingText: ' 1000 ' })).toBe(false);
    const changes = [
      { enabled: false },
      { durations: ['1h' as const] },
      { defaultDuration: '7d' as const },
      { fileAllowed: false },
      { fileMibText: '12' },
      { emailAllowed: false },
      { emailRequiresPassphrase: true },
      { expressEnabled: true },
      { expressPerHourPerIpText: '11' },
      { expressPerHourPerTokenText: '101' },
      { expressMaxPendingText: '1001' },
    ];
    for (const change of changes) {
      expect(secretDraftChanged(base, { ...base, ...change }), JSON.stringify(change)).toBe(true);
    }
  });
});
