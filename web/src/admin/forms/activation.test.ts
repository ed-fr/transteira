import { describe, expect, it } from 'vitest';
import { ACTIVATION_TOKEN, cleanActivationUrl, readActivationToken } from './activation';

const TOKEN = 'act_Lm3Qz8Xv1Bn6Kd0R4Tp7Yw2HcF5Jg9Ns4Ue7Ai1ObZ';

describe('activation link', () => {
  it('reads a well-formed token from the hash', () => {
    expect(readActivationToken(`#${TOKEN}`)).toBe(TOKEN);
    expect(readActivationToken(TOKEN)).toBe(TOKEN);
    expect(readActivationToken('#act_' + 'a'.repeat(124))).toHaveLength(128);
  });

  it('refuses a missing or malformed token', () => {
    expect(readActivationToken('')).toBeNull();
    expect(readActivationToken('#')).toBeNull();
    expect(readActivationToken('#act_short')).toBeNull();
    expect(readActivationToken('#as_' + 'a'.repeat(43))).toBeNull();
    expect(readActivationToken('#act_' + 'a'.repeat(125))).toBeNull();
    expect(readActivationToken(`#${TOKEN}&x=1`)).toBeNull();
    expect(ACTIVATION_TOKEN.test(`${TOKEN}\n`)).toBe(false);
  });

  it('builds the URL without the fragment', () => {
    expect(cleanActivationUrl({ pathname: '/admin/activate', search: '' })).toBe('/admin/activate');
    expect(cleanActivationUrl({ pathname: '/admin/activate', search: '?lang=fr' })).toBe(
      '/admin/activate?lang=fr',
    );
  });
});
