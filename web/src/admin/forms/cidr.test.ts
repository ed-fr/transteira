import { describe, expect, it } from 'vitest';
import { MAX_INTERNAL_CIDRS, isCatchAll, parseCidr, parseCidrList } from './cidr';

describe('parseCidr', () => {
  it.each([
    ['10.0.0.0/8', '10.0.0.0/8'],
    [' 192.168.1.0/24 ', '192.168.1.0/24'],
    ['192.168.1.10', '192.168.1.10/32'],
    ['0.0.0.0/0', '0.0.0.0/0'],
    ['255.255.255.255/32', '255.255.255.255/32'],
    ['2001:DB8::/32', '2001:db8::/32'],
    ['2001:db8:0:0:0:0:0:1', '2001:db8::1/128'],
    ['::', '::/128'],
    ['::/0', '::/0'],
    ['::1', '::1/128'],
    ['1:2:3:4:5:6:7::', '1:2:3:4:5:6:7:0/128'],
    ['1:0:0:2:0:0:0:3', '1:0:0:2::3/128'],
    ['1:0:0:2:0:0:3:4', '1::2:0:0:3:4/128'],
    ['1:2:3:4:5:6:7:8', '1:2:3:4:5:6:7:8/128'],
    ['fe80:0:0:0:0:0:0:0/10', 'fe80::/10'],
    ['::ffff:10.1.2.3', '10.1.2.3/32'],
    ['::ffff:10.0.0.0/104', '10.0.0.0/8'],
    ['::ffff:0.0.0.0/96', '0.0.0.0/0'],
    ['64:ff9b::1.2.3.4', '64:ff9b::102:304/128'],
    ['1:2:3:4:5:6:1.2.3.4', '1:2:3:4:5:6:102:304/128'],
  ])('accepts %s as %s', (input, value) => {
    expect(parseCidr(input)).toEqual({ ok: true, value });
  });

  it.each([
    ['', 'syntax'],
    ['10.0.0', 'syntax'],
    ['10.0.0.256', 'syntax'],
    ['010.0.0.1', 'syntax'],
    ['10.0.0.0/', 'syntax'],
    ['10.0.0.0/08', 'syntax'],
    ['10.0.0.0/a', 'syntax'],
    ['10.0.0.0/8/8', 'syntax'],
    ['10.0.0.0/33', 'prefix-range'],
    ['2001:db8::/129', 'prefix-range'],
    ['1::2::3', 'syntax'],
    [':1::', 'syntax'],
    ['1:2:3:4:5:6:7:8::', 'syntax'],
    ['1:2:3:4:5:6:7', 'syntax'],
    ['12345::', 'syntax'],
    ['::1.2.3', 'syntax'],
    ['1.2.3.4::', 'syntax'],
    ['g::1', 'syntax'],
    ['[::1]', 'syntax'],
    ['fe80::1%eth0', 'zone'],
  ])('refuses %s (%s)', (input, error) => {
    expect(parseCidr(input)).toEqual({ ok: false, error });
  });

  it('refuses host bits with the masked range as suggestion', () => {
    expect(parseCidr('10.1.2.3/8')).toEqual({ ok: false, error: 'host-bits', suggestion: '10.0.0.0/8' });
    expect(parseCidr('2001:db8::1/32')).toEqual({
      ok: false,
      error: 'host-bits',
      suggestion: '2001:db8::/32',
    });
    expect(parseCidr('::ffff:10.1.0.0/104')).toEqual({
      ok: false,
      error: 'host-bits',
      suggestion: '10.0.0.0/8',
    });
  });
});

describe('catch-all detection', () => {
  it('recognises the two catch-all ranges', () => {
    expect(isCatchAll('0.0.0.0/0')).toBe(true);
    expect(isCatchAll('::/0')).toBe(true);
    expect(isCatchAll('10.0.0.0/8')).toBe(false);
  });

  it('parses the text area with line numbers', () => {
    const r = parseCidrList('10.0.0.0/8\n\n10.1.2.3/8\nbad\n10.0.0.0/8\n::ffff:0.0.0.0/96');
    expect(r.values).toEqual(['10.0.0.0/8', '0.0.0.0/0']);
    expect(r.errors).toEqual([
      { line: 3, raw: '10.1.2.3/8', error: 'host-bits', suggestion: '10.0.0.0/8' },
      { line: 4, raw: 'bad', error: 'syntax' },
    ]);
    expect(r.duplicates).toEqual([5]);
    expect(r.catchAll).toBe(true);
    expect(parseCidrList('192.168.0.0/16').catchAll).toBe(false);
  });

  it('flags more ranges than allowed', () => {
    const text = Array.from({ length: MAX_INTERNAL_CIDRS + 1 }, (_, i) => `10.${i >> 8}.${i & 255}.0/24`);
    expect(parseCidrList(text.join('\n')).tooMany).toBe(true);
  });
});
