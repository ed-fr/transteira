import { describe, expect, it } from 'vitest';
import {
  EXPRESS_BOUNDS,
  EXPRESS_LIMITS,
  MAX_FILE_MIB,
  MIB,
  MIN_FILE_MIB,
  SECRET_DURATIONS,
  bytesToMibText,
  expressCeilings,
  expressHintParams,
  isRaiseRefused,
  parseBoundedInt,
  parseFileMib,
  purgeResultText,
  rebaseExpress,
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

describe('express limits of a delegated admin (lower only, T-418)', () => {
  const raised: SecretSettings = {
    ...saved,
    expressPerHourPerIp: 50,
    expressPerHourPerToken: 20,
    expressMaxPending: 5000,
  };

  it('keeps the bounds for the super admin', () => {
    expect(expressCeilings(raised, true)).toEqual({
      perHourPerIp: 1000,
      perHourPerToken: 10000,
      maxPending: 100000,
    });
    expect(EXPRESS_BOUNDS).toEqual({ perHourPerIp: 1000, perHourPerToken: 10000, maxPending: 100000 });
  });

  it('caps each limit at the greater of its default and its stored value', () => {
    expect(expressCeilings(raised, false)).toEqual({
      perHourPerIp: 50,
      perHourPerToken: 100,
      maxPending: 5000,
    });
    expect(expressCeilings(saved, false)).toEqual({
      perHourPerIp: 10,
      perHourPerToken: 100,
      maxPending: 1000,
    });
    expect(expressCeilings(undefined, false)).toEqual({
      perHourPerIp: 10,
      perHourPerToken: 100,
      maxPending: 1000,
    });
  });

  it('reads a zero stored value as the default and never goes past the bound', () => {
    expect(
      expressCeilings(
        { ...saved, expressPerHourPerIp: 0, expressPerHourPerToken: 99999, expressMaxPending: 3 },
        false,
      ),
    ).toEqual({ perHourPerIp: 10, perHourPerToken: 10000, maxPending: 1000 });
  });

  it('accepts a lower value, the default and the stored raised value', () => {
    const ceilings = expressCeilings(raised, false);
    for (const [ip, token, pending] of [
      ['3', '40', '500'],
      ['10', '100', '1000'],
      ['50', '20', '5000'],
      ['30', '100', '2000'],
    ] as const) {
      const draft = {
        ...toDraft(raised),
        expressPerHourPerIpText: ip,
        expressPerHourPerTokenText: token,
        expressMaxPendingText: pending,
      };
      expect(validateSecretSettings(draft, fields, t, ceilings), `${ip} ${token} ${pending}`).toEqual([]);
    }
  });

  it('refuses a raise above the ceiling, on its own field, before sending', () => {
    const ceilings = expressCeilings(raised, false);
    const draft = {
      ...toDraft(raised),
      expressPerHourPerIpText: '51',
      expressPerHourPerTokenText: '101',
      expressMaxPendingText: '5001',
    };
    expect(validateSecretSettings(draft, fields, t, ceilings)).toEqual([
      { id: 'xi', label: 'Per IP', message: 'adminSecrets.settings.errors.expressLimitRaise {"max":50}' },
      { id: 'xt', label: 'Per token', message: 'adminSecrets.settings.errors.expressLimitRaise {"max":100}' },
      { id: 'xp', label: 'Pending', message: 'adminSecrets.settings.errors.expressLimitRaise {"max":5000}' },
    ]);
    // The same values are fine for the super admin.
    expect(validateSecretSettings(draft, fields, t, expressCeilings(raised, true))).toEqual([]);
  });

  it('states the ceiling in the out-of-bounds message and in the hint', () => {
    const ceilings = expressCeilings(saved, false);
    const out = validateSecretSettings(
      { ...toDraft(saved), expressPerHourPerIpText: '0' },
      fields,
      t,
      ceilings,
    );
    expect(out[0]?.message).toBe('adminSecrets.settings.errors.expressLimit {"min":1,"max":10}');
    expect(expressHintParams(EXPRESS_LIMITS.maxPending, ceilings.maxPending)).toEqual({
      min: 1,
      max: 1000,
      def: 1000,
    });
    expect(expressHintParams(EXPRESS_LIMITS.perHourPerIp, 1000)).toEqual({ min: 1, max: 1000, def: 10 });
  });

  it('recognises the refusal of a raise by the server', () => {
    expect(isRaiseRefused({ status: 403, code: 'forbidden' })).toBe(true);
    expect(isRaiseRefused({ status: 403, code: 'read-only-role' })).toBe(false);
    expect(isRaiseRefused({ status: 403, code: 'csrf-invalid' })).toBe(false);
    expect(isRaiseRefused({ status: 400, code: 'validation-failed' })).toBe(false);
    expect(isRaiseRefused({ status: undefined, code: undefined })).toBe(false);
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

  it('never sends the read-only state of the instance kill switch', () => {
    const body = secretSettingsBody(toDraft({ ...saved, expressInstanceDisabled: true }));
    expect('expressInstanceDisabled' in body).toBe(false);
  });

  it('sends only the express members that differ from the stored settings', () => {
    const stored: SecretSettings = {
      ...saved,
      expressEnabled: true,
      expressPerHourPerIp: 10,
      expressPerHourPerToken: 100,
      expressMaxPending: 1000,
    };
    const untouched = secretSettingsBody(toDraft(stored), stored);
    for (const key of [
      'expressEnabled',
      'expressPerHourPerIp',
      'expressPerHourPerToken',
      'expressMaxPending',
    ]) {
      expect(key in untouched, key).toBe(false);
    }
    // The 2.1 members always replace the stored ones.
    expect(untouched).toEqual({
      enabled: true,
      durations: ['1h', '1d', '7d'],
      defaultDuration: '1d',
      fileAllowed: true,
      fileMaxBytes: 10 * MIB,
      emailAllowed: true,
      emailRequiresPassphrase: false,
    });
    // A changed member is sent, the others stay out (a stale form with another 2.1 change never
    // reopens the anonymous mode nor restores a limit the super admin changed meanwhile).
    const changed = secretSettingsBody(
      { ...toDraft(stored), expressEnabled: false, expressMaxPendingText: ' 900 ' },
      stored,
    );
    expect(changed).toMatchObject({ expressEnabled: false, expressMaxPending: 900 });
    expect('expressPerHourPerIp' in changed).toBe(false);
    expect('expressPerHourPerToken' in changed).toBe(false);
    // The same number typed differently is no change; a missing stored limit is its default.
    const { expressPerHourPerIp: _ip, expressEnabled: _on, ...partial } = stored;
    const same = secretSettingsBody(
      { ...toDraft(stored), expressEnabled: false, expressPerHourPerIpText: '010' },
      partial,
    );
    expect('expressPerHourPerIp' in same).toBe(false);
    expect('expressEnabled' in same).toBe(false);
    expect(secretSettingsBody({ ...toDraft(stored), expressPerHourPerTokenText: '7' }, stored)).toMatchObject(
      {
        expressPerHourPerToken: 7,
      },
    );
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

describe('rebaseExpress', () => {
  const stored: SecretSettings = {
    ...saved,
    expressEnabled: true,
    expressPerHourPerIp: 10,
    expressPerHourPerToken: 100,
    expressMaxPending: 1000,
  };
  // Stored since: the super admin closed the anonymous mode and lowered two limits.
  const fresh: SecretSettings = {
    ...stored,
    expressEnabled: false,
    expressPerHourPerIp: 2,
    expressPerHourPerToken: 20,
    expressMaxPending: 1000,
  };

  it('takes the stored values for the express fields the admin did not change', () => {
    const base = toDraft(stored);
    const draft = {
      ...base,
      fileMibText: '5',
      expressMaxPendingText: '50000',
      expressPerHourPerTokenText: ' 100 ',
    };
    const next = rebaseExpress(draft, base, fresh);
    expect(next.draft).toEqual({
      ...draft,
      expressEnabled: false,
      expressPerHourPerIpText: '2',
      expressPerHourPerTokenText: '20',
      expressMaxPendingText: '50000',
    });
    expect(next.saved).toEqual({
      ...base,
      expressEnabled: false,
      expressPerHourPerIpText: '2',
      expressPerHourPerTokenText: '20',
      expressMaxPendingText: '1000',
    });
    // Only the change of the admin is then sent; the dirty state follows.
    const body = secretSettingsBody(next.draft, fresh);
    expect(body).toMatchObject({ fileMaxBytes: 5 * MIB, expressMaxPending: 50000 });
    for (const key of ['expressEnabled', 'expressPerHourPerIp', 'expressPerHourPerToken']) {
      expect(key in body, key).toBe(false);
    }
    expect(secretDraftChanged(next.saved, next.draft)).toBe(true);
    expect(
      secretDraftChanged(next.saved, { ...next.draft, fileMibText: '10', expressMaxPendingText: '1000' }),
    ).toBe(false);
  });

  it('keeps a changed switch and copies, never shares, the durations', () => {
    const base = toDraft(stored);
    const draft = { ...base, expressEnabled: false, expressPerHourPerIpText: '3' };
    const next = rebaseExpress(draft, base, { ...fresh, expressEnabled: true });
    expect(next.draft.expressEnabled).toBe(false);
    expect(next.draft.expressPerHourPerIpText).toBe('3');
    expect(next.saved.expressEnabled).toBe(true);
    expect(next.draft.durations).not.toBe(draft.durations);
    expect(next.saved.durations).not.toBe(base.durations);
    expect(next.draft.durations).toEqual(draft.durations);
  });
});
