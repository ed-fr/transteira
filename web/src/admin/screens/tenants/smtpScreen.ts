// Logic of the tenant SMTP screen (CLAUDE.md section 12.1), kept out of the component so that
// it is unit tested in Node: client-side validation of the settings form, dirty state, result
// of the test send and rows of the DNS check.
import type { components } from '../../../shared/api/schema';
import type { ErrorView } from '../../../shared/api/problem';
import type { FieldRef, SummaryError } from '../../components/form';
import type { StatusVariant } from '../../components/fields';
import { MAX_DKIM_SELECTORS, type DkimSelectors } from '../../forms/dkim';
import {
  buildSmtpUpdate,
  smtpFormFrom,
  type SmtpForm,
  type SmtpSettings,
  type SmtpSettingsUpdate,
} from '../../forms/smtp';
import type { Msg, Translate } from './network';

type Schemas = components['schemas'];
/** Result of the test send. */
export type SmtpTestResult = Schemas['SmtpTestResult'];
/** Result of the DNS check of the sender domain. */
export type MailDnsCheck = Schemas['MailDnsCheck'];

/** Fields of the SMTP form, for the error summary (keys are the API field names). */
export interface SmtpFields {
  host: FieldRef;
  port: FieldRef;
  security: FieldRef;
  username: FieldRef;
  password: FieldRef;
  fromAddress: FieldRef;
  fromName: FieldRef;
}

/** Loose email shape check; the server validates the address. */
export function looksLikeEmail(s: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s.trim());
}

/** Parses the port field: an integer from 1 to 65535, or null. */
export function parsePort(text: string): number | null {
  const s = text.trim();
  if (!/^[0-9]{1,5}$/.test(s)) {
    return null;
  }
  const n = Number(s);
  return n >= 1 && n <= 65535 ? n : null;
}

/** Form state from the port text: an invalid port is kept as NaN (refused by the validation). */
export function formWithPort(form: Omit<SmtpForm, 'port'>, portText: string): SmtpForm {
  return { ...form, port: parsePort(portText) ?? Number.NaN };
}

/** Result of the client-side validation of the SMTP form. */
export type SmtpValidation = { ok: true; update: SmtpSettingsUpdate } | { ok: false; errors: SummaryError[] };

/**
 * Validates the SMTP form: required host and sender address, port from 1 to 65535, lengths of
 * the API, then the rules of buildSmtpUpdate (a username with the security none, a kept password
 * while the server changes, an empty new password, a password without username).
 */
export function validateSmtp(
  stored: SmtpSettings | null,
  form: SmtpForm,
  fields: SmtpFields,
  t: Translate,
): SmtpValidation {
  const errs: Partial<Record<keyof SmtpFields, Msg>> = {};
  if (form.host.trim() === '') {
    errs.host = { key: 'fieldErrors.required' };
  } else if (form.host.trim().length > 253) {
    errs.host = { key: 'fieldErrors.too-long' };
  }
  if (!Number.isInteger(form.port) || form.port < 1 || form.port > 65535) {
    errs.port = { key: 'fieldErrors.invalid-port' };
  }
  if (form.username.trim().length > 320) {
    errs.username = { key: 'fieldErrors.too-long' };
  }
  if (form.fromAddress.trim() === '') {
    errs.fromAddress = { key: 'fieldErrors.required' };
  } else if (!looksLikeEmail(form.fromAddress)) {
    errs.fromAddress = { key: 'fieldErrors.invalid-email' };
  }
  if (form.fromName.trim().length > 100) {
    errs.fromName = { key: 'fieldErrors.too-long' };
  }
  const built = buildSmtpUpdate(stored, form);
  if (!built.ok) {
    switch (built.error) {
      case 'username-needs-security':
        errs.username ??= { key: 'adminTenants.smtp.username.needsSecurity' };
        break;
      case 'password-required':
        errs.password = { key: 'adminTenants.smtp.password.reenter' };
        break;
      case 'password-empty':
        errs.password = { key: 'fieldErrors.required' };
        break;
      case 'password-needs-username':
        errs.username ??= { key: 'adminTenants.smtp.username.requiredWithPassword' };
        break;
    }
  }
  const errors: SummaryError[] = [];
  for (const [name, ref] of Object.entries(fields) as [keyof SmtpFields, FieldRef][]) {
    const m = errs[name];
    if (m !== undefined) {
      errors.push({ id: ref.id, label: ref.label, message: t(m.key, m.params) });
    }
  }
  if (errors.length > 0 || !built.ok) {
    return { ok: false, errors };
  }
  return { ok: true, update: built.update };
}

/** Reports whether the form differs from the stored settings (or from an empty form). */
export function smtpDirty(stored: SmtpSettings | null, form: SmtpForm): boolean {
  const base = smtpFormFrom(stored);
  return (
    base.host !== form.host ||
    base.port !== form.port ||
    base.security !== form.security ||
    base.username !== form.username ||
    form.passwordMode !== 'keep' ||
    form.password !== '' ||
    base.fromAddress !== form.fromAddress ||
    base.fromName !== form.fromName
  );
}

/** Stages of the SMTP dialogue that have a translation. */
const STAGES = [
  'settings',
  'connect',
  'tls',
  'greeting',
  'starttls',
  'auth',
  'envelope',
  'data',
  'done',
  'unknown',
];

/** Translation key of a stage of the test send (a stage added later falls back to unknown). */
export function stageKey(stage: string): string {
  return `adminTenants.smtp.test.stage.${STAGES.includes(stage) ? stage : 'unknown'}`;
}

/** Display of the result of a test send. */
export interface TestResultView {
  success: boolean;
  /** Heading of the result card. */
  title: Msg;
  /** "Stage: …", with the stage translated. */
  stage: Msg;
  /** "Duration: … ms". */
  duration: Msg;
  /** Sanitised server message, shown as text; undefined when there is none. */
  error: string | undefined;
}

/** Maps the result of the test send to its display (t translates the stage). */
export function testResultView(result: SmtpTestResult, t: Translate): TestResultView {
  const stage = t(stageKey(result.stage));
  return {
    success: result.success,
    title: result.success
      ? { key: 'adminTenants.smtp.test.success', params: { duration: result.durationMs } }
      : { key: 'adminTenants.smtp.test.failure' },
    stage: { key: 'adminTenants.smtp.test.stageReached', params: { stage } },
    duration: { key: 'adminTenants.smtp.test.duration', params: { duration: result.durationMs } },
    error: result.error === undefined || result.error === '' ? undefined : result.error,
  };
}

/**
 * General message of a failed test send: the rate limit (429) with its delay when the server
 * gives one, otherwise the translated problem.
 */
export function testFailureMessage(view: ErrorView, t: Translate): string {
  if (view.status === 429 && view.retryAfterSeconds !== undefined) {
    return t('adminTenants.smtp.test.rateLimited', { count: view.retryAfterSeconds });
  }
  return view.message;
}

/** Validates the recipient of the test send; returns the error message key, if any. */
export function testRecipientError(to: string): Msg | undefined {
  if (to.trim() === '') {
    return { key: 'fieldErrors.required' };
  }
  return looksLikeEmail(to) ? undefined : { key: 'fieldErrors.invalid-email' };
}

/** Error of the DKIM selectors field, if any. */
export function selectorsError(parsed: DkimSelectors): Msg | undefined {
  if (parsed.invalid.length > 0) {
    return { key: 'fieldErrors.invalid-format' };
  }
  if (parsed.tooMany) {
    return { key: 'fieldErrors.too-many-values', params: { max: MAX_DKIM_SELECTORS } };
  }
  return undefined;
}

/** Status of a DNS record check. */
export type DnsStatus = 'ok' | 'warning' | 'missing' | 'error';

/** Badge variant of a DNS status (the badge text says the status). */
export function dnsVariant(status: DnsStatus): StatusVariant {
  return status;
}

/** One row of the DNS check table. */
export interface DnsRow {
  id: 'spf' | 'dkim' | 'dmarc';
  /** Translation key of the record name. */
  label: string;
  status: DnsStatus;
  /** Translation key of the status. */
  statusLabel: string;
  /** Record found, shown as text. */
  record: string | undefined;
  /** Diagnostic message of the server, shown as text. */
  message: string | undefined;
  /** DKIM only: one line per selector probed. */
  selectors: Msg[];
}

function blankToUndefined(s: string | undefined): string | undefined {
  return s === undefined || s === '' ? undefined : s;
}

/** Rows of the DNS check table, in the order SPF, DKIM, DMARC. */
export function dnsRows(check: MailDnsCheck): DnsRow[] {
  const row = (
    id: DnsRow['id'],
    c: { status: DnsStatus; record?: string; message?: string },
    selectors: Msg[] = [],
  ): DnsRow => ({
    id,
    label: `adminTenants.smtp.dns.${id}`,
    status: c.status,
    statusLabel: `adminTenants.smtp.dns.status.${c.status}`,
    record: blankToUndefined(c.record),
    message: blankToUndefined(c.message),
    selectors,
  });
  const selectors: Msg[] =
    check.dkim.selectors.length === 0
      ? [{ key: 'adminTenants.smtp.dns.noSelectors' }]
      : check.dkim.selectors.map((s) => ({
          key: s.found ? 'adminTenants.smtp.dns.selectorFound' : 'adminTenants.smtp.dns.selectorMissing',
          params: { selector: s.selector },
        }));
  return [
    row('spf', check.spf),
    row('dkim', { status: check.dkim.status }, selectors),
    row('dmarc', check.dmarc),
  ];
}

/**
 * Path of the DNS check, relative to the API base, with one dkimSelector query parameter per
 * selector (the form explode style of the specification).
 */
export function dnsCheckPath(tenantId: string, selectors: readonly string[]): string {
  const query = new URLSearchParams();
  for (const s of selectors) {
    query.append('dkimSelector', s);
  }
  const qs = query.toString();
  return `/admin/tenants/${encodeURIComponent(tenantId)}/smtp/dns-check${qs === '' ? '' : `?${qs}`}`;
}
