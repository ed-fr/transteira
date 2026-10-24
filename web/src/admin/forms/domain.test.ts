import { describe, expect, it } from 'vitest';
import { MAX_INTERNAL_DOMAINS, parseDomain, parseDomainList } from './domain';

describe('parseDomain', () => {
  it.each([
    ['entity-a.example.com', 'entity-a.example.com'],
    ['  Entity-A.Example.COM ', 'entity-a.example.com'],
    ['bücher.example', 'xn--bcher-kva.example'],
    ['xn--bcher-kva.example', 'xn--bcher-kva.example'],
    ['example.xn--p1ai', 'example.xn--p1ai'],
    ['a1.example.org', 'a1.example.org'],
  ])('accepts %s as %s', (input, value) => {
    expect(parseDomain(input)).toEqual({ ok: true, value });
  });

  it.each([
    ['', 'syntax'],
    ['user@example.com', 'syntax'],
    ['example.com:25', 'syntax'],
    ['exa mple.com', 'syntax'],
    ['example.com/x', 'syntax'],
    ['[::1]', 'syntax'],
    ['under_score.example.com', 'syntax'],
    ['ex!ample.com', 'syntax'],
    ['192.168.1.1', 'ip-literal'],
    ['localhost', 'single-label'],
    ['-bad.example.com', 'label'],
    ['bad-.example.com', 'label'],
    ['a..example.com', 'label'],
    [`${'a'.repeat(64)}.example.com`, 'label'],
    [`${'a.'.repeat(126)}com`, 'too-long'],
    ['example.c', 'tld'],
    ['example.c0m', 'tld'],
    ['127.1', 'tld'],
    ['bü cher.example', 'syntax'],
    ['exa\u{1F600}%.com', 'idn'],
    ['bücher_x.example', 'idn'],
  ])('refuses %s (%s)', (input, error) => {
    expect(parseDomain(input)).toEqual({ ok: false, error });
  });

  it('refuses a trailing dot, suggesting the domain without it', () => {
    expect(parseDomain('Example.com.')).toEqual({
      ok: false,
      error: 'trailing-dot',
      suggestion: 'example.com',
    });
    expect(parseDomain('localhost.')).toEqual({ ok: false, error: 'trailing-dot' });
  });

  it('parses the text area with line numbers', () => {
    const r = parseDomainList('example.com\nEXAMPLE.com\nbad_domain.com\n\nentity-b.example.com');
    expect(r.values).toEqual(['example.com', 'entity-b.example.com']);
    expect(r.errors).toEqual([{ line: 3, raw: 'bad_domain.com', error: 'syntax' }]);
    expect(r.duplicates).toEqual([2]);
    const many = Array.from({ length: MAX_INTERNAL_DOMAINS + 1 }, (_, i) => `d${i}.example.com`);
    expect(parseDomainList(many.join('\n')).tooMany).toBe(true);
  });
});
