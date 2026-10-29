import { describe, expect, it } from 'vitest';
import {
  isDirty,
  isKnownTimeZone,
  parseFactor,
  parseInteger,
  sameThresholds,
  timeZoneSuggestions,
  toBody,
  toForm,
  toggleWeekday,
  validateForm,
  validateOfficeHours,
  type AbuseThresholds,
} from './abuse';

const base: AbuseThresholds = {
  maxDailyBytesPerSender: 107374182400,
  maxDailyTransfersPerSender: 50,
  maxRecipientsPerTransfer: 50,
  blockOnExceed: false,
  unusualVolumeFactor: 5,
  unusualMinHistoryDays: 7,
  largeExternalTransferBytes: 10737418240,
  timeZone: 'Europe/Paris',
  officeHours: { start: '08:00', end: '19:00', weekdays: [1, 2, 3, 4, 5] },
  maxInvitationsPerInviter: 20,
  externalMaxDailyBytes: 21474836480,
  externalMaxDailyDeposits: 10,
};
const disabled: AbuseThresholds = {
  ...base,
  maxDailyBytesPerSender: null,
  maxDailyTransfersPerSender: null,
  maxRecipientsPerTransfer: null,
  unusualVolumeFactor: null,
  largeExternalTransferBytes: null,
  officeHours: null,
  externalMaxDailyBytes: null,
  externalMaxDailyDeposits: null,
};

describe('form mapping', () => {
  it('round-trips the saved thresholds', () => {
    expect(toBody(toForm(base))).toEqual(base);
    expect(toBody(toForm(disabled))).toEqual(disabled);
  });

  it('sends null for every disabled rule and every member', () => {
    const form = toForm(base);
    form.maxDailyBytesPerSender.enabled = false;
    form.officeHoursEnabled = false;
    form.externalMaxDailyDeposits.enabled = false;
    const body = toBody(form);
    expect(body?.maxDailyBytesPerSender).toBeNull();
    expect(body?.officeHours).toBeNull();
    expect(body?.externalMaxDailyDeposits).toBeNull();
    expect(Object.keys(body ?? {})).toHaveLength(12);
  });

  it('is not dirty until something changes', () => {
    const form = toForm(base);
    expect(isDirty(base, form)).toBe(false);
    form.blockOnExceed = true;
    expect(isDirty(base, form)).toBe(true);
    form.blockOnExceed = false;
    form.officeWeekdays = toggleWeekday(form.officeWeekdays, 6, true);
    expect(isDirty(base, form)).toBe(true);
  });

  it('compares thresholds', () => {
    expect(sameThresholds(base, { ...base })).toBe(true);
    expect(sameThresholds(base, disabled)).toBe(false);
    expect(sameThresholds(disabled, { ...disabled })).toBe(true);
  });
});

describe('numbers', () => {
  it('parses whole numbers in range', () => {
    expect(parseInteger('50', 1)).toBe(50);
    expect(parseInteger('0', 1)).toBeUndefined();
    expect(parseInteger('101', 1, 100)).toBeUndefined();
    expect(parseInteger('1.5', 1)).toBeUndefined();
    expect(parseInteger('', 1)).toBeUndefined();
  });

  it('parses the factor with one decimal, dot or comma', () => {
    expect(parseFactor('1,5')).toBe(1.5);
    expect(parseFactor('5')).toBe(5);
    expect(parseFactor('99.9')).toBe(99.9);
    expect(parseFactor('1.4')).toBeUndefined();
    expect(parseFactor('100.1')).toBeUndefined();
    expect(parseFactor('2.55')).toBeUndefined();
    expect(parseFactor('abc')).toBeUndefined();
  });
});

describe('office hours', () => {
  it('validates times, order and weekdays', () => {
    expect(validateOfficeHours('08:00', '24:00', [1])).toBeUndefined();
    expect(validateOfficeHours('8:00', '19:00', [1])).toBe('start');
    expect(validateOfficeHours('08:00', '25:00', [1])).toBe('end');
    expect(validateOfficeHours('08:00', '08:00', [1])).toBe('order');
    expect(validateOfficeHours('08:00', '19:00', [])).toBe('weekdays');
  });

  it('toggles weekdays in order', () => {
    expect(toggleWeekday([1, 3], 2, true)).toEqual([1, 2, 3]);
    expect(toggleWeekday([1, 2, 3], 2, false)).toEqual([1, 3]);
  });
});

describe('validation', () => {
  it('accepts the saved form', () => {
    expect(validateForm(toForm(base))).toEqual([]);
  });

  it('reports each invalid field with the API name', () => {
    const form = toForm(base);
    form.maxDailyTransfersPerSender.text = '';
    form.maxRecipientsPerTransfer.text = '500';
    form.unusualVolumeFactor.text = '1.2';
    form.unusualMinHistoryDays = '0';
    form.largeExternalTransferBytes.bytes = null;
    form.timeZone = 'Mars/Olympus';
    form.officeEnd = '07:00';
    form.maxInvitationsPerInviter = '2000';
    expect(validateForm(form).map((i) => i.field)).toEqual([
      'maxDailyTransfersPerSender',
      'maxRecipientsPerTransfer',
      'unusualVolumeFactor',
      'unusualMinHistoryDays',
      'largeExternalTransferBytes',
      'timeZone',
      'officeHours',
      'maxInvitationsPerInviter',
    ]);
    expect(toBody(form)).toBeUndefined();
  });

  it('ignores the value of a disabled rule', () => {
    const form = toForm(base);
    form.maxDailyTransfersPerSender = { enabled: false, text: 'garbage' };
    expect(validateForm(form)).toEqual([]);
  });
});

describe('time zones', () => {
  it('knows IANA zones', () => {
    expect(isKnownTimeZone('Europe/Paris')).toBe(true);
    expect(isKnownTimeZone('UTC')).toBe(true);
    expect(isKnownTimeZone('')).toBe(false);
    expect(isKnownTimeZone('Nowhere/Land')).toBe(false);
  });

  it('suggests UTC first', () => {
    const zones = timeZoneSuggestions();
    expect(zones[0]).toBe('UTC');
    expect(zones).toContain('Europe/Paris');
  });
});
