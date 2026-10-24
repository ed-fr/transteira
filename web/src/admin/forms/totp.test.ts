import { describe, expect, it } from 'vitest';
import { formatSecret, groupSecret, isPngBase64, parseOtpauthLabel, qrCodeDataUrl } from './totp';

// A 1x1 PNG.
const PNG =
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';

describe('QR code', () => {
  it('accepts a base64 PNG only', () => {
    expect(isPngBase64(PNG)).toBe(true);
    expect(qrCodeDataUrl(PNG)).toBe(`data:image/png;base64,${PNG}`);
    expect(isPngBase64('')).toBe(false);
    expect(isPngBase64('R0lGODlhAQABAAAAACw=')).toBe(false);
    expect(isPngBase64(PNG.slice(0, -1))).toBe(false);
    expect(isPngBase64('iVBORw0KGgo"><script>=')).toBe(false);
    expect(qrCodeDataUrl('not base64!')).toBeNull();
  });
});

describe('secret', () => {
  it('groups the secret by 4', () => {
    expect(groupSecret('jbsw y3dp ehpk3pxp')).toEqual(['JBSW', 'Y3DP', 'EHPK', '3PXP']);
    expect(groupSecret('ABCDEF', 3)).toEqual(['ABC', 'DEF']);
    expect(formatSecret('JBSWY3DPEHPK3PXPZ')).toBe('JBSW Y3DP EHPK 3PXP Z');
    expect(groupSecret('')).toEqual([]);
  });
});

describe('parseOtpauthLabel', () => {
  it('reads the issuer and the account', () => {
    expect(
      parseOtpauthLabel('otpauth://totp/TransTeira:admin%40example.com?secret=X&issuer=TransTeira'),
    ).toEqual({ issuer: 'TransTeira', account: 'admin@example.com' });
    expect(parseOtpauthLabel('OTPAUTH://TOTP/Label%3A%20admin?issuer=Param')).toEqual({
      issuer: 'Param',
      account: 'admin',
    });
    expect(parseOtpauthLabel('otpauth://totp/Prefix:admin')).toEqual({ issuer: 'Prefix', account: 'admin' });
    expect(parseOtpauthLabel('otpauth://totp/admin?secret=X')).toEqual({ issuer: null, account: 'admin' });
  });

  it('refuses other URIs and malformed labels', () => {
    expect(parseOtpauthLabel('javascript:alert(1)')).toBeNull();
    expect(parseOtpauthLabel('otpauth://hotp/a:b')).toBeNull();
    expect(parseOtpauthLabel('otpauth://totp/%E0%A4%A')).toBeNull();
    expect(parseOtpauthLabel('otpauth://totp/Issuer:?secret=X')).toBeNull();
  });
});
