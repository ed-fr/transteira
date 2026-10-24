import { describe, expect, it } from 'vitest';
import {
  SUGGESTED_PORTS,
  buildSmtpUpdate,
  portAfterSecurityChange,
  serverIdentityChanged,
  smtpFormFrom,
  type SmtpForm,
  type SmtpSettings,
  usernameWithoutSecurity,
} from './smtp';

const stored: SmtpSettings = {
  host: 'smtp.example.com',
  port: 587,
  security: 'starttls',
  username: 'mailer@example.com',
  passwordSet: true,
  fromAddress: 'transfer@example.com',
  fromName: 'Transfer',
};

function form(over: Partial<SmtpForm> = {}): SmtpForm {
  return { ...smtpFormFrom(stored), ...over };
}

describe('smtpFormFrom', () => {
  it('fills the form from the stored settings', () => {
    expect(smtpFormFrom(stored)).toEqual({
      host: 'smtp.example.com',
      port: 587,
      security: 'starttls',
      username: 'mailer@example.com',
      passwordMode: 'keep',
      password: '',
      fromAddress: 'transfer@example.com',
      fromName: 'Transfer',
    });
    expect(smtpFormFrom({ ...stored, username: null, fromName: null })).toMatchObject({
      username: '',
      fromName: '',
    });
  });

  it('starts an empty form without stored settings', () => {
    expect(smtpFormFrom(null)).toMatchObject({ host: '', port: 587, security: 'starttls' });
  });
});

describe('buildSmtpUpdate', () => {
  it('keeps the password when the server is unchanged', () => {
    expect(buildSmtpUpdate(stored, form({ fromName: '  ', fromAddress: ' a@example.com ' }))).toEqual({
      ok: true,
      update: {
        host: 'smtp.example.com',
        port: 587,
        security: 'starttls',
        username: 'mailer@example.com',
        fromAddress: 'a@example.com',
        fromName: null,
      },
    });
  });

  it('refuses a username with the security none, as the server does', () => {
    expect(buildSmtpUpdate(stored, form({ security: 'none' }))).toEqual({
      ok: false,
      field: 'username',
      error: 'username-needs-security',
    });
    expect(
      buildSmtpUpdate(
        null,
        form({ security: 'none', username: 'u', passwordMode: 'replace', password: 'p' }),
      ),
    ).toMatchObject({ ok: false, error: 'username-needs-security' });
    expect(buildSmtpUpdate(null, form({ security: 'none', username: '  ' })).ok).toBe(true);
  });

  it.each([
    { host: 'smtp2.example.com' },
    { port: 465 },
    { username: 'other@example.com' },
    { username: '' },
  ])('requires re-entering or removing the password when %o changes', (over) => {
    expect(buildSmtpUpdate(stored, form(over))).toEqual({
      ok: false,
      field: 'password',
      error: 'password-required',
    });
  });

  it('allows a server change with a kept password when none is stored', () => {
    const r = buildSmtpUpdate({ ...stored, passwordSet: false }, form({ host: 'relay' }));
    expect(r.ok).toBe(true);
    expect(buildSmtpUpdate(null, form({ host: 'relay', username: '' })).ok).toBe(true);
  });

  it('replaces the password', () => {
    const r = buildSmtpUpdate(
      stored,
      form({ host: 'smtp2.example.com', passwordMode: 'replace', password: 's3cret' }),
    );
    expect(r).toMatchObject({ ok: true, update: { password: 's3cret' } });
    expect(r.ok && 'removePassword' in r.update).toBe(false);
  });

  it('refuses an empty new password or one without username', () => {
    expect(buildSmtpUpdate(stored, form({ passwordMode: 'replace', password: '' }))).toEqual({
      ok: false,
      field: 'password',
      error: 'password-empty',
    });
    expect(buildSmtpUpdate(stored, form({ passwordMode: 'replace', password: 'x', username: ' ' }))).toEqual({
      ok: false,
      field: 'password',
      error: 'password-needs-username',
    });
  });

  it('removes the password, never together with a new one', () => {
    const r = buildSmtpUpdate(
      stored,
      form({ host: 'relay', username: '', security: 'none', passwordMode: 'remove', password: 'typed' }),
    );
    expect(r).toEqual({
      ok: true,
      update: {
        host: 'relay',
        port: 587,
        security: 'none',
        username: null,
        removePassword: true,
        fromAddress: 'transfer@example.com',
        fromName: 'Transfer',
      },
    });
    const none = buildSmtpUpdate({ ...stored, passwordSet: false }, form({ passwordMode: 'remove' }));
    expect(none.ok).toBe(true);
    expect(none.ok && 'password' in none.update).toBe(false);
    expect(none.ok && 'removePassword' in none.update).toBe(false);
  });
});

describe('serverIdentityChanged', () => {
  it('compares host, port and username', () => {
    expect(serverIdentityChanged(null, form())).toBe(false);
    expect(serverIdentityChanged(stored, form({ host: ' smtp.example.com ' }))).toBe(false);
    expect(serverIdentityChanged(stored, form({ security: 'tls', fromName: 'x' }))).toBe(false);
    expect(serverIdentityChanged({ ...stored, username: null }, form({ username: '' }))).toBe(false);
    expect(serverIdentityChanged({ ...stored, username: undefined }, form({ username: 'u' }))).toBe(true);
  });
});

describe('usernameWithoutSecurity', () => {
  it('flags a username with the security none', () => {
    expect(usernameWithoutSecurity(form())).toBe(false);
    expect(usernameWithoutSecurity(form({ security: 'none' }))).toBe(true);
    expect(usernameWithoutSecurity(form({ security: 'none', username: ' ' }))).toBe(false);
    expect(usernameWithoutSecurity(form({ security: 'tls' }))).toBe(false);
  });
});

describe('portAfterSecurityChange', () => {
  it('suggests the usual port unless a custom one is set', () => {
    expect(SUGGESTED_PORTS).toEqual({ none: 25, starttls: 587, tls: 465 });
    expect(portAfterSecurityChange(587, 'tls')).toBe(465);
    expect(portAfterSecurityChange(25, 'starttls')).toBe(587);
    expect(portAfterSecurityChange(0, 'none')).toBe(25);
    expect(portAfterSecurityChange(NaN, 'none')).toBe(25);
    expect(portAfterSecurityChange(2525, 'tls')).toBe(2525);
  });
});
