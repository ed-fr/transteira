import { describe, expect, it } from 'vitest';
import { EMAIL_MAX_LENGTH, isEmail } from './email';

describe('isEmail', () => {
  it('accepts a bare address and refuses display names and obvious mistakes', () => {
    expect(isEmail('alice@example.com')).toBe(true);
    expect(isEmail('Alice <alice@example.com>')).toBe(false);
    expect(isEmail('alice@example')).toBe(false);
    expect(isEmail('alice example.com')).toBe(false);
    expect(isEmail('')).toBe(false);
  });

  it('refuses an address longer than the maximum', () => {
    const local = 'a'.repeat(EMAIL_MAX_LENGTH - '@example.com'.length);
    expect(isEmail(`${local}@example.com`)).toBe(true);
    expect(isEmail(`a${local}@example.com`)).toBe(false);
  });
});
