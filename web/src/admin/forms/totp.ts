// TOTP enrolment display (TotpEnrollment): QR code shown as a data: URL only when its base64 is
// valid, secret grouped for reading, account and issuer read from the otpauth URI as plain text
// (the URI is never used as a link).

/** Pattern of a base64 value (standard alphabet, padded). */
export const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

// Base64 of the 8-byte PNG signature (89 50 4E 47 0D 0A 1A 0A).
const PNG_SIGNATURE_B64 = 'iVBORw0KGgo';

/** Reports whether value is a well-formed base64 PNG. */
export function isPngBase64(value: string): boolean {
  return value.length % 4 === 0 && BASE64.test(value) && value.startsWith(PNG_SIGNATURE_B64);
}

/** Returns the data: URL of the QR code, or null when the base64 is not a valid PNG. */
export function qrCodeDataUrl(qrCodePng: string): string | null {
  return isPngBase64(qrCodePng) ? `data:image/png;base64,${qrCodePng}` : null;
}

/** Splits a base32 secret into groups of size characters (spaces removed, uppercase). */
export function groupSecret(secret: string, size = 4): string[] {
  const s = secret.replace(/\s+/g, '').toUpperCase();
  const out: string[] = [];
  for (let i = 0; i < s.length; i += size) {
    out.push(s.slice(i, i + size));
  }
  return out;
}

/** Returns the secret grouped by 4 and separated by spaces, for display. */
export function formatSecret(secret: string): string {
  return groupSecret(secret).join(' ');
}

/** Account and issuer of an otpauth URI. */
export interface OtpauthLabel {
  issuer: string | null;
  account: string;
}

function decode(s: string): string | null {
  try {
    return decodeURIComponent(s);
  } catch {
    return null;
  }
}

/**
 * Reads the account and issuer of an otpauth://totp/ URI, by string parsing only. The issuer
 * parameter takes precedence over the label prefix ("Issuer:account"). Returns null when the URI
 * is not a TOTP otpauth URI or its label is malformed.
 */
export function parseOtpauthLabel(uri: string): OtpauthLabel | null {
  const prefix = 'otpauth://totp/';
  if (uri.slice(0, prefix.length).toLowerCase() !== prefix) {
    return null;
  }
  const rest = uri.slice(prefix.length);
  const q = rest.indexOf('?');
  const label = decode(q < 0 ? rest : rest.slice(0, q));
  if (label === null) {
    return null;
  }
  const colon = label.indexOf(':');
  const account = (colon < 0 ? label : label.slice(colon + 1)).trim();
  if (account === '') {
    return null;
  }
  const params = new URLSearchParams(q < 0 ? '' : rest.slice(q + 1));
  const issuer = (params.get('issuer') ?? (colon < 0 ? '' : label.slice(0, colon))).trim();
  return { issuer: issuer === '' ? null : issuer, account };
}
