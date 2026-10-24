import { describe, expect, it } from 'vitest';
import type { ErrorView } from '../../../shared/api/problem';
import { parseDkimSelectors } from '../../forms/dkim';
import { smtpFormFrom, type SmtpForm, type SmtpSettings } from '../../forms/smtp';
import {
  dnsCheckPath,
  dnsRows,
  dnsVariant,
  formWithPort,
  looksLikeEmail,
  parsePort,
  selectorsError,
  smtpDirty,
  stageKey,
  testFailureMessage,
  testRecipientError,
  testResultView,
  validateSmtp,
  type SmtpFields,
} from './smtpScreen';

const t = (key: string, params?: Record<string, string | number>): string =>
  params === undefined ? key : `${key} ${JSON.stringify(params)}`;

const stored: SmtpSettings = {
  host: 'smtp.example.com',
  port: 587,
  security: 'starttls',
  username: 'mailer@example.com',
  passwordSet: true,
  fromAddress: 'transfer@example.com',
  fromName: 'Transfer',
};

const fields: SmtpFields = {
  host: { id: 'host', label: 'Host' },
  port: { id: 'port', label: 'Port' },
  security: { id: 'security', label: 'Security' },
  username: { id: 'username', label: 'Username' },
  password: { id: 'password', label: 'Password' },
  fromAddress: { id: 'from', label: 'From' },
  fromName: { id: 'name', label: 'Name' },
};

function form(over: Partial<SmtpForm> = {}): SmtpForm {
  return { ...smtpFormFrom(stored), ...over };
}

function view(over: Partial<ErrorView>): ErrorView {
  return {
    code: undefined,
    status: undefined,
    message: 'generic',
    fields: {},
    attemptsRemaining: undefined,
    retryAfterSeconds: undefined,
    maxTransferBytes: undefined,
    files: undefined,
    ...over,
  };
}

describe('small parsers', () => {
  it('checks the email shape', () => {
    expect(looksLikeEmail(' a@example.com ')).toBe(true);
    expect(looksLikeEmail('a@example')).toBe(false);
    expect(looksLikeEmail('a b@example.com')).toBe(false);
  });

  it('parses the port', () => {
    expect(parsePort(' 587 ')).toBe(587);
    expect(parsePort('0')).toBeNull();
    expect(parsePort('65536')).toBeNull();
    expect(parsePort('25a')).toBeNull();
    expect(parsePort('')).toBeNull();
  });

  it('keeps an invalid port as NaN', () => {
    const { port: _port, ...rest } = form();
    expect(formWithPort(rest, '465').port).toBe(465);
    expect(formWithPort(rest, 'x').port).toBeNaN();
  });
});

describe('validateSmtp', () => {
  it('builds the update of a valid form', () => {
    expect(validateSmtp(stored, form({ fromName: 'New' }), fields, t)).toEqual({
      ok: true,
      update: {
        host: 'smtp.example.com',
        port: 587,
        security: 'starttls',
        username: 'mailer@example.com',
        fromAddress: 'transfer@example.com',
        fromName: 'New',
      },
    });
  });

  it('reports the field errors in form order', () => {
    const r = validateSmtp(null, form({ host: ' ', port: Number.NaN, fromAddress: '' }), fields, t);
    expect(r).toEqual({
      ok: false,
      errors: [
        { id: 'host', label: 'Host', message: 'fieldErrors.required' },
        { id: 'port', label: 'Port', message: 'fieldErrors.invalid-port' },
        { id: 'from', label: 'From', message: 'fieldErrors.required' },
      ],
    });
  });

  it('checks the lengths and the sender address', () => {
    const r = validateSmtp(
      stored,
      form({
        host: 'h'.repeat(254),
        username: 'u'.repeat(321),
        fromAddress: 'nope',
        fromName: 'n'.repeat(101),
        port: 70000,
        passwordMode: 'remove',
      }),
      fields,
      t,
    );
    expect(r.ok ? [] : r.errors.map((e) => [e.id, e.message])).toEqual([
      ['host', 'fieldErrors.too-long'],
      ['port', 'fieldErrors.invalid-port'],
      ['username', 'fieldErrors.too-long'],
      ['from', 'fieldErrors.invalid-email'],
      ['name', 'fieldErrors.too-long'],
    ]);
  });

  it('blocks a username with the security none on the username field', () => {
    expect(validateSmtp(stored, form({ security: 'none' }), fields, t)).toEqual({
      ok: false,
      errors: [{ id: 'username', label: 'Username', message: 'adminTenants.smtp.username.needsSecurity' }],
    });
  });

  it('asks to enter the password again when the server changes', () => {
    expect(validateSmtp(stored, form({ host: 'other.example.com' }), fields, t)).toEqual({
      ok: false,
      errors: [{ id: 'password', label: 'Password', message: 'adminTenants.smtp.password.reenter' }],
    });
  });

  it('requires the new password in the replace mode', () => {
    const r = validateSmtp(stored, form({ passwordMode: 'replace' }), fields, t);
    expect(r.ok ? [] : r.errors).toEqual([
      { id: 'password', label: 'Password', message: 'fieldErrors.required' },
    ]);
  });

  it('requires a username with a new password', () => {
    const r = validateSmtp(null, form({ username: '', passwordMode: 'replace', password: 'pw' }), fields, t);
    expect(r.ok ? [] : r.errors).toEqual([
      { id: 'username', label: 'Username', message: 'adminTenants.smtp.username.requiredWithPassword' },
    ]);
  });
});

describe('smtpDirty', () => {
  it('is clean for the stored settings and dirty after a change', () => {
    expect(smtpDirty(stored, form())).toBe(false);
    expect(smtpDirty(stored, form({ host: 'x' }))).toBe(true);
    expect(smtpDirty(stored, form({ port: 25 }))).toBe(true);
    expect(smtpDirty(stored, form({ security: 'tls' }))).toBe(true);
    expect(smtpDirty(stored, form({ username: '' }))).toBe(true);
    expect(smtpDirty(stored, form({ passwordMode: 'remove' }))).toBe(true);
    expect(smtpDirty(stored, form({ password: 'p' }))).toBe(true);
    expect(smtpDirty(stored, form({ fromAddress: 'b@example.com' }))).toBe(true);
    expect(smtpDirty(stored, form({ fromName: '' }))).toBe(true);
    expect(smtpDirty(null, smtpFormFrom(null))).toBe(false);
  });
});

describe('test send', () => {
  it('translates known stages and falls back to unknown', () => {
    expect(stageKey('auth')).toBe('adminTenants.smtp.test.stage.auth');
    expect(stageKey('quantum')).toBe('adminTenants.smtp.test.stage.unknown');
  });

  it('maps a success', () => {
    expect(testResultView({ success: true, durationMs: 412, stage: 'done' }, t)).toEqual({
      success: true,
      title: { key: 'adminTenants.smtp.test.success', params: { duration: 412 } },
      stage: {
        key: 'adminTenants.smtp.test.stageReached',
        params: { stage: 'adminTenants.smtp.test.stage.done' },
      },
      duration: { key: 'adminTenants.smtp.test.duration', params: { duration: 412 } },
      error: undefined,
    });
  });

  it('maps a failure with its server message', () => {
    const v = testResultView({ success: false, durationMs: 5003, stage: 'connect', error: 'timeout' }, t);
    expect(v.title).toEqual({ key: 'adminTenants.smtp.test.failure' });
    expect(v.error).toBe('timeout');
    expect(
      testResultView({ success: false, durationMs: 1, stage: 'connect', error: '' }, t).error,
    ).toBeUndefined();
  });

  it('shows the rate limit with its delay', () => {
    expect(testFailureMessage(view({ status: 429, retryAfterSeconds: 30 }), t)).toBe(
      'adminTenants.smtp.test.rateLimited {"count":30}',
    );
    expect(testFailureMessage(view({ status: 429 }), t)).toBe('generic');
    expect(testFailureMessage(view({ status: 500, retryAfterSeconds: 3 }), t)).toBe('generic');
  });

  it('validates the recipient', () => {
    expect(testRecipientError(' ')).toEqual({ key: 'fieldErrors.required' });
    expect(testRecipientError('x')).toEqual({ key: 'fieldErrors.invalid-email' });
    expect(testRecipientError('admin@example.com')).toBeUndefined();
  });
});

describe('DNS check', () => {
  it('validates the selectors', () => {
    expect(selectorsError(parseDkimSelectors('selector1, selector2'))).toBeUndefined();
    expect(selectorsError(parseDkimSelectors('-bad'))).toEqual({ key: 'fieldErrors.invalid-format' });
    expect(selectorsError(parseDkimSelectors('a b c d e f'))).toEqual({
      key: 'fieldErrors.too-many-values',
      params: { max: 5 },
    });
  });

  it('builds the path with one parameter per selector', () => {
    expect(dnsCheckPath('t 1', [])).toBe('/admin/tenants/t%201/smtp/dns-check');
    expect(dnsCheckPath('t1', ['selector1', 'selector2'])).toBe(
      '/admin/tenants/t1/smtp/dns-check?dkimSelector=selector1&dkimSelector=selector2',
    );
  });

  it('maps the statuses to badge variants', () => {
    expect(dnsVariant('ok')).toBe('ok');
    expect(dnsVariant('error')).toBe('error');
  });

  it('builds the rows SPF, DKIM, DMARC', () => {
    const rows = dnsRows({
      domain: 'example.com',
      spf: { status: 'ok', record: 'v=spf1 -all' },
      dkim: {
        status: 'warning',
        selectors: [
          { selector: 'selector1', found: true },
          { selector: 'selector2', found: false },
        ],
      },
      dmarc: { status: 'missing', record: '', message: 'No record.' },
    });
    expect(rows).toEqual([
      {
        id: 'spf',
        label: 'adminTenants.smtp.dns.spf',
        status: 'ok',
        statusLabel: 'adminTenants.smtp.dns.status.ok',
        record: 'v=spf1 -all',
        message: undefined,
        selectors: [],
      },
      {
        id: 'dkim',
        label: 'adminTenants.smtp.dns.dkim',
        status: 'warning',
        statusLabel: 'adminTenants.smtp.dns.status.warning',
        record: undefined,
        message: undefined,
        selectors: [
          { key: 'adminTenants.smtp.dns.selectorFound', params: { selector: 'selector1' } },
          { key: 'adminTenants.smtp.dns.selectorMissing', params: { selector: 'selector2' } },
        ],
      },
      {
        id: 'dmarc',
        label: 'adminTenants.smtp.dns.dmarc',
        status: 'missing',
        statusLabel: 'adminTenants.smtp.dns.status.missing',
        record: undefined,
        message: 'No record.',
        selectors: [],
      },
    ]);
  });

  it('says when no selector was checked', () => {
    const rows = dnsRows({
      domain: 'example.com',
      spf: { status: 'error' },
      dkim: { status: 'missing', selectors: [] },
      dmarc: { status: 'ok' },
    });
    expect(rows[1]?.selectors).toEqual([{ key: 'adminTenants.smtp.dns.noSelectors' }]);
  });
});
