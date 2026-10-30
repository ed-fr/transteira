import { describe, expect, it } from 'vitest';
import type { ErrorView } from '../../../shared/api/problem';
import {
  engineDisabled,
  engineLabel,
  engineLabelKey,
  decimalSeparator,
  emailChanged,
  emailRemoved,
  formFromSettings,
  formatPercentInput,
  isSettingsDirty,
  parsePercent,
  percentFromRatio,
  ratioFromPercent,
  roundRatio,
  settingsFailure,
  settingsPatch,
  thresholdIssue,
  thresholdIssueText,
  validateSettingsForm,
  type SettingsFieldRefs,
  type SettingsForm,
  type SystemSettings,
} from './settings';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

const refs: SettingsFieldRefs = {
  diskAlertThreshold: { id: 'threshold', label: 'Threshold' },
  alertEmail: { id: 'email', label: 'Email' },
  emailConfirm: { id: 'confirm', label: 'Confirm' },
};

const plain: SystemSettings = { diskAlertThreshold: 0.85, alertEmail: null };
const withEmail: SystemSettings = { diskAlertThreshold: 0.855, alertEmail: 'alerts@example.com' };

function form(partial: Partial<SettingsForm>, base: SystemSettings = plain): SettingsForm {
  return { ...formFromSettings(base, '.'), ...partial };
}

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

describe('threshold conversion', () => {
  it('converts between ratios and percentages at the basis point', () => {
    expect(percentFromRatio(0.85)).toBe(85);
    expect(percentFromRatio(0.855)).toBe(85.5);
    expect(percentFromRatio(0.8567)).toBe(85.67);
    expect(percentFromRatio(0.57)).toBe(57);
    expect(ratioFromPercent(85)).toBe(0.85);
    expect(ratioFromPercent(85.5)).toBe(0.855);
    expect(ratioFromPercent(57)).toBe(0.57);
    expect(ratioFromPercent(99.99)).toBe(0.9999);
    expect(roundRatio(0.85004)).toBe(0.85);
  });

  it('formats the field with the separator of the locale', () => {
    expect(formatPercentInput(0.85, ',')).toBe('85');
    expect(formatPercentInput(0.855, ',')).toBe('85,5');
    expect(formatPercentInput(0.855, '.')).toBe('85.5');
    expect(decimalSeparator('fr')).toBe(',');
    expect(decimalSeparator('en')).toBe('.');
    expect(decimalSeparator('')).toBe('.');
    expect(decimalSeparator('not a locale!')).toBe('.');
  });

  it('parses percentages with at most two decimals', () => {
    expect(parsePercent(' 85 ')).toBe(85);
    expect(parsePercent('85,5')).toBe(85.5);
    expect(parsePercent('85.25')).toBe(85.25);
    expect(parsePercent('85.255')).toBeUndefined();
    expect(parsePercent('85%')).toBeUndefined();
    expect(parsePercent('-60')).toBeUndefined();
    expect(parsePercent('1e2')).toBeUndefined();
    expect(parsePercent('')).toBeUndefined();
  });

  it('checks the range 50 to 99', () => {
    expect(thresholdIssue('')).toBe('required');
    expect(thresholdIssue('abc')).toBe('invalid');
    expect(thresholdIssue('49.99')).toBe('range');
    expect(thresholdIssue('99.01')).toBe('range');
    expect(thresholdIssue('100')).toBe('range');
    expect(thresholdIssue('50')).toBeUndefined();
    expect(thresholdIssue('99')).toBeUndefined();
    expect(thresholdIssue('85,5')).toBeUndefined();
  });

  it('translates the issues', () => {
    expect(thresholdIssueText('required', t)).toBe('sysSettings.threshold.required');
    expect(thresholdIssueText('invalid', t)).toBe('sysSettings.threshold.invalid');
    expect(thresholdIssueText('range', t)).toBe('sysSettings.threshold.range {"min":50,"max":99}');
  });
});

describe('form model and patch', () => {
  it('fills the form', () => {
    expect(formFromSettings(withEmail, ',')).toEqual({
      threshold: '85,5',
      email: 'alerts@example.com',
      emailConfirm: '',
    });
    expect(formFromSettings(plain, '.').email).toBe('');
  });

  it('sends nothing when nothing changed', () => {
    expect(settingsPatch(plain, form({}))).toEqual({});
    expect(settingsPatch(withEmail, form({}, withEmail))).toEqual({});
    expect(settingsPatch(plain, form({ threshold: '85.0' }))).toEqual({});
    expect(settingsPatch(withEmail, form({ email: ' alerts@example.com ' }, withEmail))).toEqual({});
  });

  it('sends a stored non-whole percentage unchanged', () => {
    expect(settingsPatch(withEmail, formFromSettings(withEmail, ','))).toEqual({});
  });

  it('sends the changed threshold as a ratio', () => {
    expect(settingsPatch(plain, form({ threshold: '90' }))).toEqual({ diskAlertThreshold: 0.9 });
    expect(settingsPatch(plain, form({ threshold: '57,25' }))).toEqual({ diskAlertThreshold: 0.5725 });
  });

  it('leaves an unparseable threshold out', () => {
    expect(settingsPatch(plain, form({ threshold: 'abc' }))).toEqual({});
  });

  it('sends a new address, trimmed', () => {
    expect(settingsPatch(plain, form({ email: ' ops@example.com ' }))).toEqual({
      alertEmail: 'ops@example.com',
    });
  });

  it('sends null to remove the address', () => {
    const patch = settingsPatch(withEmail, form({ email: '  ' }, withEmail));
    expect(patch).toEqual({ alertEmail: null });
    expect(emailRemoved(withEmail, form({ email: '' }, withEmail))).toBe(true);
    expect(emailRemoved(plain, form({ email: '' }))).toBe(false);
  });

  it('detects a changed address', () => {
    expect(emailChanged(plain, form({ email: 'ops@example.com' }))).toBe(true);
    expect(emailChanged(withEmail, form({}, withEmail))).toBe(false);
    expect(emailChanged(withEmail, form({ email: '' }, withEmail))).toBe(false);
  });

  it('tracks edits', () => {
    expect(isSettingsDirty(plain, form({}))).toBe(false);
    expect(isSettingsDirty(plain, form({ threshold: '90' }))).toBe(true);
    expect(isSettingsDirty(plain, form({ threshold: '' }))).toBe(true);
    expect(isSettingsDirty(plain, form({ threshold: 'abc' }))).toBe(true);
    expect(isSettingsDirty(plain, form({ email: 'ops@example.com' }))).toBe(true);
    expect(isSettingsDirty(withEmail, form({ email: '' }, withEmail))).toBe(true);
  });

  it('compares the parsed threshold, not its text', () => {
    expect(isSettingsDirty(plain, form({ threshold: '85.0' }))).toBe(false);
    expect(isSettingsDirty(plain, form({ threshold: ' 85,00 ' }))).toBe(false);
    expect(isSettingsDirty(withEmail, form({ threshold: '85.51' }, withEmail))).toBe(true);
  });

  it('is not made dirty by a change of the interface language', () => {
    // Form filled in French ("85,5"), then the language switches to English (separator ".").
    const filledInFrench = { ...formFromSettings(withEmail, ','), emailConfirm: '' };
    expect(filledInFrench.threshold).toBe('85,5');
    expect(isSettingsDirty(withEmail, filledInFrench)).toBe(false);
    const filledInEnglish = formFromSettings(withEmail, '.');
    expect(isSettingsDirty(withEmail, filledInEnglish)).toBe(false);
  });
});

describe('validation and errors', () => {
  it('accepts a valid form', () => {
    expect(validateSettingsForm(plain, form({}), refs, t)).toEqual([]);
    expect(validateSettingsForm(withEmail, form({ email: '' }, withEmail), refs, t)).toEqual([]);
    expect(
      validateSettingsForm(
        plain,
        form({ email: 'ops@example.com', emailConfirm: ' OPS@example.com ' }),
        refs,
        t,
      ),
    ).toEqual([]);
  });

  it('reports the threshold and an invalid address', () => {
    expect(validateSettingsForm(plain, form({ threshold: '40', email: 'not-an-email' }), refs, t)).toEqual([
      { id: 'threshold', label: 'Threshold', message: 'sysSettings.threshold.range {"min":50,"max":99}' },
      { id: 'email', label: 'Email', message: 'sysSettings.email.invalid' },
    ]);
    expect(validateSettingsForm(plain, form({ email: `${'a'.repeat(250)}@example.com` }), refs, t)).toEqual([
      { id: 'email', label: 'Email', message: 'sysSettings.email.invalid' },
    ]);
  });

  it('requires the confirmation of a changed address', () => {
    expect(validateSettingsForm(plain, form({ email: 'ops@example.com' }), refs, t)).toEqual([
      { id: 'confirm', label: 'Confirm', message: 'sysSettings.email.confirmRequired' },
    ]);
    expect(
      validateSettingsForm(
        plain,
        form({ email: 'ops@example.com', emailConfirm: 'op@example.com' }),
        refs,
        t,
      ),
    ).toEqual([{ id: 'confirm', label: 'Confirm', message: 'sysSettings.email.confirmMismatch' }]);
  });

  it('maps the field errors of the API', () => {
    const out = settingsFailure(
      view({
        status: 400,
        code: 'validation-failed',
        fields: {
          diskAlertThreshold: { code: 'invalid-format', message: 'x' },
          alertEmail: { code: 'invalid-email', message: 'y' },
        },
      }),
      refs,
      t,
    );
    expect(out).toEqual({
      ok: false,
      errors: [
        { id: 'threshold', label: 'Threshold', message: 'sysSettings.threshold.range {"min":50,"max":99}' },
        { id: 'email', label: 'Email', message: 'sysSettings.email.invalid' },
      ],
    });
  });

  it('keeps the general message for an unknown field', () => {
    const out = settingsFailure(
      view({
        status: 400,
        code: 'validation-failed',
        fields: { '': { code: 'invalid-format', message: 'z' } },
      }),
      refs,
      t,
    );
    expect(out).toEqual({ ok: false, message: 'general', errors: [] });
  });

  it('shows any other error as a general message', () => {
    expect(settingsFailure(view({ status: 403, code: 'forbidden' }), refs, t)).toEqual({
      ok: false,
      message: 'general',
    });
  });
});

describe('antivirus engine', () => {
  it('labels the known engines and keeps an unknown one raw', () => {
    expect(engineLabelKey('clamd')).toBe('sysSettings.antivirus.engine.clamd');
    expect(engineLabelKey('none')).toBe('sysSettings.antivirus.engine.none');
    expect(engineLabelKey('other')).toBeUndefined();
    expect(engineLabel('icap', t)).toBe('sysSettings.antivirus.engine.icap');
    expect(engineLabel('other', t)).toBe('other');
  });

  it('flags only the disabled engine', () => {
    expect(engineDisabled('none')).toBe(true);
    expect(engineDisabled('clamd')).toBe(false);
    expect(engineDisabled(undefined)).toBe(false);
  });
});
