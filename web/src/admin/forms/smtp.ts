// SMTP settings form of a tenant: construction of the SmtpSettingsUpdate body from the stored
// settings and the form, following the password rules of the API (tenantadmin.UpdateSMTP).

import type { components } from '../../shared/api/schema';

type Schemas = components['schemas'];
/** Stored SMTP settings, as returned by the API (the password is never returned). */
export type SmtpSettings = Schemas['SmtpSettings'];
/** Body of the SMTP update. */
export type SmtpSettingsUpdate = Schemas['SmtpSettingsUpdate'];
/** Transport security of the SMTP connection. */
export type SmtpSecurity = Schemas['SmtpSecurity'];

/** What to do with the stored password. */
export type PasswordMode = 'keep' | 'replace' | 'remove';

/** State of the SMTP form. */
export interface SmtpForm {
  host: string;
  port: number;
  security: SmtpSecurity;
  /** Empty when the server needs no authentication. */
  username: string;
  passwordMode: PasswordMode;
  /** New password, used only in the replace mode. */
  password: string;
  fromAddress: string;
  fromName: string;
}

/**
 * Client-side errors of the form:
 * - username-needs-security (username field): a username with the security none; the server
 *   always refuses it (authentication requires starttls or tls), so the credentials never travel
 *   in clear: choose STARTTLS or TLS, or remove the username;
 * - password-required (password field): a stored password is kept while the host, port or
 *   username changes (the server refuses it so that the password is never sent to another
 *   server): re-enter or remove;
 * - password-empty (password field): the replace mode without a password;
 * - password-needs-username (password field): a new password without a username, refused by the
 *   server.
 */
export type SmtpFormError =
  'username-needs-security' | 'password-required' | 'password-empty' | 'password-needs-username';

/** Result of buildSmtpUpdate. */
export type SmtpUpdateResult =
  | { ok: true; update: SmtpSettingsUpdate }
  | { ok: false; field: 'username' | 'password'; error: SmtpFormError };

/** Port usually associated with each security mode (25, 587 submission, 465 implicit TLS). */
export const SUGGESTED_PORTS: Readonly<Record<SmtpSecurity, number>> = {
  none: 25,
  starttls: 587,
  tls: 465,
};

/** Returns the form state for stored settings, or an empty form when there are none yet. */
export function smtpFormFrom(stored: SmtpSettings | null): SmtpForm {
  if (stored === null) {
    return {
      host: '',
      port: SUGGESTED_PORTS.starttls,
      security: 'starttls',
      username: '',
      passwordMode: 'keep',
      password: '',
      fromAddress: '',
      fromName: '',
    };
  }
  return {
    host: stored.host,
    port: stored.port,
    security: stored.security,
    username: stored.username ?? '',
    passwordMode: 'keep',
    password: '',
    fromAddress: stored.fromAddress,
    fromName: stored.fromName ?? '',
  };
}

/** Returns a text field value, or null when it is blank. */
function orNull(v: string): string | null {
  return v.trim() === '' ? null : v;
}

/** Reports whether the host, port or username of the form differ from the stored ones. */
export function serverIdentityChanged(stored: SmtpSettings | null, form: SmtpForm): boolean {
  if (stored === null) {
    return false;
  }
  return (
    stored.host !== form.host.trim() ||
    stored.port !== form.port ||
    (stored.username ?? null) !== orNull(form.username)
  );
}

/**
 * Builds the SMTP update body:
 * - a username with the security none is refused (username-needs-security), as by the server;
 * - keep sends neither password nor removePassword; it is refused (password-required) when a
 *   password is stored and the host, port or username changes;
 * - replace sends the new password (it requires a username);
 * - remove sends removePassword: true, or nothing when no password is stored;
 * - removePassword is only sent when true, never together with password (the specification
 *   forbids the pair, whatever its values); a blank username or sender name is null.
 */
export function buildSmtpUpdate(stored: SmtpSettings | null, form: SmtpForm): SmtpUpdateResult {
  const username = orNull(form.username);
  if (username !== null && form.security === 'none') {
    return { ok: false, field: 'username', error: 'username-needs-security' };
  }
  const update: SmtpSettingsUpdate = {
    host: form.host.trim(),
    port: form.port,
    security: form.security,
    username,
    fromAddress: form.fromAddress.trim(),
    fromName: orNull(form.fromName),
  };
  const passwordSet = stored?.passwordSet ?? false;
  switch (form.passwordMode) {
    case 'keep':
      if (passwordSet && serverIdentityChanged(stored, form)) {
        return { ok: false, field: 'password', error: 'password-required' };
      }
      break;
    case 'replace':
      if (form.password === '') {
        return { ok: false, field: 'password', error: 'password-empty' };
      }
      if (username === null) {
        return { ok: false, field: 'password', error: 'password-needs-username' };
      }
      update.password = form.password;
      break;
    case 'remove':
      if (passwordSet) {
        update.removePassword = true;
      }
      break;
  }
  return { ok: true, update };
}

/**
 * Reports whether the form asks for authentication without transport security (a username with
 * the security none). The server refuses it; the form warns as soon as the combination appears,
 * before the blocking error of buildSmtpUpdate on submit.
 */
export function usernameWithoutSecurity(form: SmtpForm): boolean {
  return form.security === 'none' && orNull(form.username) !== null;
}

/**
 * Returns the port to show after the security changes: the suggested port of the new mode when
 * the current one is unset or the suggested port of another mode, otherwise the current one.
 */
export function portAfterSecurityChange(currentPort: number, security: SmtpSecurity): number {
  const suggested = Object.values(SUGGESTED_PORTS);
  if (!Number.isInteger(currentPort) || currentPort < 1 || suggested.includes(currentPort)) {
    return SUGGESTED_PORTS[security];
  }
  return currentPort;
}
