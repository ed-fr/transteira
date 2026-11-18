// View helpers of the deposit screens (CLAUDE.md section 13.2): width of the public card for each
// step, subtitle of the form, element ids of the fields (error summary links, focus). Pure
// functions, unit tested in Node; the components only render what they return.
import type { IconName } from '../../shared/components/icons';
import type { CardSize } from '../frame/card.svelte';
import type { ScanStatus } from './flow.svelte';
import type { FormField, Message } from './form';

/** Tab of the form step: send files, or share a one-time secret. */
export type DepositMode = 'files' | 'secret';

/**
 * Width of the public card: split (files and details side by side) on the form step of the files
 * tab, medium on the secret tab, narrow on every other step (one column of content).
 */
export function depositCardSize(step: string, mode: DepositMode): CardSize {
  if (step !== 'form') {
    return 'narrow';
  }
  return mode === 'secret' ? 'medium' : 'split';
}

/** What the subtitle of the form states. */
export interface SubtitleOptions {
  /** Formatted size limit of a transfer (e.g. "20 GB"). */
  max: string;
  /** The transfer is end-to-end encrypted (in the browser). */
  e2e: boolean;
  /** The files are analysed by the antivirus (see DepositFlow.antivirusMentioned). */
  antivirus: boolean;
}

/**
 * Parts of the subtitle of the form, shown separated by middle dots: the size limit, how the
 * files are encrypted, and the antivirus analysis when it applies.
 */
export function subtitleParts(options: SubtitleOptions): Message[] {
  const parts: Message[] = [{ key: 'deposit.form.subtitle.limit', params: { max: options.max } }];
  parts.push({
    key: options.e2e ? 'deposit.form.subtitle.e2eEncryption' : 'deposit.form.subtitle.serverEncryption',
  });
  if (options.antivirus) {
    parts.push({ key: 'deposit.form.subtitle.antivirus' });
  }
  return parts;
}

/** Element id of the control of each form field (error summary links). */
export const FIELD_IDS: Readonly<Record<FormField, string>> = {
  recipients: 'tt-deposit-recipients',
  message: 'tt-deposit-message',
  expiryDays: 'tt-deposit-expiry',
  password: 'tt-deposit-password',
  maxDownloads: 'tt-deposit-max-downloads',
  recipientVerification: 'tt-deposit-recipient-verification',
  linkOnly: 'tt-deposit-link-only',
  endToEnd: 'tt-deposit-e2e',
  files: 'tt-deposit-files',
};

/** Element ids of the switches that reveal a field (password, maximum number of downloads). */
export const SWITCH_IDS = {
  password: 'tt-deposit-password-on',
  maxDownloads: 'tt-deposit-max-downloads-on',
} as const;

/** Which of the fields revealed by a switch are shown. */
export interface RevealedFields {
  password: boolean;
  maxDownloads: boolean;
}

/**
 * Element id to focus for a field of the error summary: the field itself, or the switch that
 * reveals it while it is hidden. The durations are radio buttons named after FIELD_IDS.expiryDays
 * (the screen focuses the checked one, else the first).
 */
export function focusTargetId(field: FormField, shown: RevealedFields): string {
  if (field === 'password' && !shown.password) {
    return SWITCH_IDS.password;
  }
  if (field === 'maxDownloads' && !shown.maxDownloads) {
    return SWITCH_IDS.maxDownloads;
  }
  return FIELD_IDS[field];
}

/** State of the form that a change of confidentiality level may change. */
export interface LevelEffects {
  /** Chosen duration, in days. */
  expiryDays: number | undefined;
  /** Number of security options in effect (DepositFlow.activeSecurityCount). */
  securityCount: number;
}

/**
 * Announcements after a change of confidentiality level: the duration it changed (no longer
 * allowed) and the new number of security options in effect (some are imposed by a level).
 */
export function levelChangeMessages(before: LevelEffects, after: LevelEffects): Message[] {
  const out: Message[] = [];
  if (after.expiryDays !== undefined && after.expiryDays !== before.expiryDays) {
    out.push({ key: 'deposit.form.level.expiryChanged', params: { count: after.expiryDays } });
  }
  if (after.securityCount !== before.securityCount) {
    out.push({ key: 'deposit.form.level.securityChanged', params: { count: after.securityCount } });
  }
  return out;
}

/**
 * The "Security options" block opens by itself when more options come into effect: at first, when
 * one is chosen, or when a change of level imposes some. It never closes by itself, and fewer
 * options leave it as it is, so that a block the depositor closed stays closed. (On a refusal of
 * the form, it opens only when one of its fields is refused: form.hasSecurityError.)
 */
export function securityOpensOnCount(before: number, after: number): boolean {
  return after > before;
}

/** Icon and tone of the antivirus status of a file in the recap (the text says the status). */
export interface ScanStatusIcon {
  icon: IconName;
  /** success and danger use the status colours, muted the muted text colour. */
  tone: 'success' | 'warning' | 'danger' | 'muted';
}

/**
 * Icon of an antivirus status: a check when no threat was found, an alert when the file was
 * deleted or withheld (danger) or delivered without analysis (warning), a clock while it waits, a
 * lock for an end-to-end encrypted file (not analysed by choice).
 */
export function scanStatusIcon(status: ScanStatus): ScanStatusIcon {
  switch (status) {
    case 'clean':
      return { icon: 'check', tone: 'success' };
    case 'infected':
    case 'scan_error':
      return { icon: 'alert', tone: 'danger' };
    case 'not_scanned_too_large':
    case 'not_scanned_encrypted':
    case 'not_scanned_disabled':
      return { icon: 'alert', tone: 'warning' };
    case 'not_scanned_e2e':
      return { icon: 'lock', tone: 'muted' };
    default:
      return { icon: 'clock', tone: 'muted' };
  }
}
