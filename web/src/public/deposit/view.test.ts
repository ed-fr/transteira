import { describe, expect, it } from 'vitest';
import en from '../../locales/en/deposit.json';
import fr from '../../locales/fr/deposit.json';
import { ICON_NAMES } from '../../shared/components/icons';
import type { ScanStatus } from './flow.svelte';
import type { FormField, Message } from './form';
import {
  depositCardSize,
  FIELD_IDS,
  focusTargetId,
  levelChangeMessages,
  scanStatusIcon,
  securityOpensOnCount,
  subtitleParts,
  SWITCH_IDS,
} from './view';

/** The message exists in both languages ("deposit." keys only). */
function translated(message: Message): boolean {
  const path = message.key.replace(/^deposit\./, '').split('.');
  return [en, fr].every((bundle) => {
    let node: unknown = bundle;
    for (const part of path) {
      node = typeof node === 'object' && node !== null ? (node as Record<string, unknown>)[part] : undefined;
    }
    return typeof node === 'string' || (typeof node === 'object' && node !== null && 'other' in node);
  });
}

describe('depositCardSize', () => {
  it('splits the card on the form step of the files tab', () => {
    expect(depositCardSize('form', 'files')).toBe('split');
    expect(depositCardSize('form', 'secret')).toBe('medium');
  });

  it('keeps the card narrow on the other steps', () => {
    for (const step of ['loading', 'email', 'code', 'preparing', 'resume', 'upload', 'finalizing', 'done']) {
      expect(depositCardSize(step, 'files')).toBe('narrow');
      expect(depositCardSize(step, 'secret')).toBe('narrow');
    }
  });
});

describe('subtitleParts', () => {
  it('states the limit, the server encryption and the antivirus', () => {
    const parts = subtitleParts({ max: '20 GB', e2e: false, antivirus: true });
    expect(parts).toEqual([
      { key: 'deposit.form.subtitle.limit', params: { max: '20 GB' } },
      { key: 'deposit.form.subtitle.serverEncryption' },
      { key: 'deposit.form.subtitle.antivirus' },
    ]);
    expect(parts.every(translated)).toBe(true);
  });

  it('states the end-to-end encryption and leaves out the antivirus', () => {
    const parts = subtitleParts({ max: '1 GB', e2e: true, antivirus: false });
    expect(parts.map((p) => p.key)).toEqual([
      'deposit.form.subtitle.limit',
      'deposit.form.subtitle.e2eEncryption',
    ]);
    expect(parts.every(translated)).toBe(true);
  });
});

describe('focusTargetId', () => {
  const shown = { password: true, maxDownloads: true };

  it('targets the field itself when it is shown', () => {
    const fields = Object.keys(FIELD_IDS) as FormField[];
    for (const field of fields) {
      expect(focusTargetId(field, shown)).toBe(FIELD_IDS[field]);
    }
    expect(FIELD_IDS.password).toBe('tt-deposit-password');
    expect(FIELD_IDS.maxDownloads).toBe('tt-deposit-max-downloads');
    expect(FIELD_IDS.endToEnd).toBe('tt-deposit-e2e');
  });

  it('targets the switch of a hidden field', () => {
    const hidden = { password: false, maxDownloads: false };
    expect(focusTargetId('password', hidden)).toBe(SWITCH_IDS.password);
    expect(focusTargetId('maxDownloads', hidden)).toBe(SWITCH_IDS.maxDownloads);
    expect(focusTargetId('message', hidden)).toBe(FIELD_IDS.message);
  });
});

describe('levelChangeMessages', () => {
  it('announces a changed duration and a new number of options', () => {
    const messages = levelChangeMessages(
      { expiryDays: 30, securityCount: 0 },
      { expiryDays: 1, securityCount: 3 },
    );
    expect(messages).toEqual([
      { key: 'deposit.form.level.expiryChanged', params: { count: 1 } },
      { key: 'deposit.form.level.securityChanged', params: { count: 3 } },
    ]);
    expect(messages.every(translated)).toBe(true);
  });

  it('announces nothing when the level changes neither', () => {
    expect(
      levelChangeMessages({ expiryDays: 7, securityCount: 1 }, { expiryDays: 7, securityCount: 1 }),
    ).toEqual([]);
    expect(
      levelChangeMessages({ expiryDays: 7, securityCount: 1 }, { expiryDays: undefined, securityCount: 1 }),
    ).toEqual([]);
  });
});

describe('scanStatusIcon', () => {
  it('gives an icon of the set and a tone for every status', () => {
    const cases: [ScanStatus, string, string][] = [
      ['clean', 'check', 'success'],
      ['infected', 'alert', 'danger'],
      ['scan_error', 'alert', 'danger'],
      ['not_scanned_too_large', 'alert', 'warning'],
      ['not_scanned_encrypted', 'alert', 'warning'],
      ['not_scanned_disabled', 'alert', 'warning'],
      ['not_scanned_e2e', 'lock', 'muted'],
      ['pending', 'clock', 'muted'],
      ['scanning', 'clock', 'muted'],
    ];
    for (const [status, icon, tone] of cases) {
      expect(scanStatusIcon(status)).toEqual({ icon, tone });
      expect(ICON_NAMES).toContain(icon);
    }
  });
});

describe('securityOpensOnCount', () => {
  it('opens the block when more options come into effect', () => {
    // At first (an option imposed by the default level), chosen, or imposed by a new level.
    expect(securityOpensOnCount(0, 1)).toBe(true);
    expect(securityOpensOnCount(1, 4)).toBe(true);
  });

  it('leaves the block as it is when the options stay the same or fewer are in effect', () => {
    // A block the depositor closed stays closed (e.g. one option on, another level imposing none).
    expect(securityOpensOnCount(0, 0)).toBe(false);
    expect(securityOpensOnCount(2, 2)).toBe(false);
    expect(securityOpensOnCount(4, 1)).toBe(false);
  });
});
