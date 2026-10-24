import { describe, expect, it } from 'vitest';
import { checkTemplate, extractVariables, insertVariable, offsetOf } from './template';

describe('extractVariables', () => {
  it('finds every placeholder with its offsets', () => {
    expect(extractVariables('Hi {{tenant_name}}, {{ download_link }}{{x}} {{Bad}} {{ }}')).toEqual([
      { name: 'tenant_name', start: 3, end: 18 },
      { name: 'download_link', start: 20, end: 39 },
      { name: 'x', start: 39, end: 44 },
    ]);
    expect(extractVariables('none')).toEqual([]);
  });
});

describe('checkTemplate', () => {
  const variables = ['tenant_name', 'download_link', 'message'];

  it('reports unknown and missing required variables', () => {
    const r = checkTemplate(
      {
        subject: '{{tenant_name}} {{nope}}',
        bodyHtml: '<a href="{{download_link}}">{{other}}</a> {{nope}}',
        bodyText: '{{message}}',
      },
      variables,
      ['download_link', 'tenant_name'],
    );
    expect(r.unknown).toEqual(['nope', 'other']);
    expect(r.missing).toEqual([
      { part: 'bodyHtml', name: 'tenant_name' },
      { part: 'bodyText', name: 'download_link' },
      { part: 'bodyText', name: 'tenant_name' },
    ]);
  });

  it('accepts a complete template, required list optional', () => {
    const parts = { subject: 's', bodyHtml: '{{download_link}}', bodyText: '{{ download_link }}' };
    expect(checkTemplate(parts, variables, ['download_link'])).toEqual({ unknown: [], missing: [] });
    expect(checkTemplate(parts, variables)).toEqual({ unknown: [], missing: [] });
  });
});

describe('insertVariable', () => {
  it('inserts at the caret and replaces a selection', () => {
    expect(insertVariable('Hello !', 'tenant_name', 6)).toEqual({
      text: 'Hello {{tenant_name}}!',
      cursor: 21,
    });
    expect(insertVariable('Hello XX!', 'x', 8, 6)).toEqual({ text: 'Hello {{x}}!', cursor: 11 });
  });

  it('clamps the offsets', () => {
    expect(insertVariable('ab', 'x', 10)).toEqual({ text: 'ab{{x}}', cursor: 7 });
    expect(insertVariable('ab', 'x', -3)).toEqual({ text: '{{x}}ab', cursor: 5 });
  });
});

describe('offsetOf', () => {
  const text = 'ab\nc\u{1F600}d\nlast';

  it('converts a line and a code-point column into a UTF-16 offset', () => {
    expect(offsetOf(text, 1, 1)).toBe(0);
    expect(offsetOf(text, 1, 2)).toBe(1);
    expect(offsetOf(text, 2, 1)).toBe(3);
    expect(offsetOf(text, 2, 3)).toBe(6);
    expect(offsetOf(text, 3, 2)).toBe(9);
  });

  it('clamps beyond a line or the text and refuses unknown positions', () => {
    expect(offsetOf(text, 1, 99)).toBe(2);
    expect(offsetOf(text, 3, 99)).toBe(text.length);
    expect(offsetOf(text, 9, 1)).toBe(text.length);
    expect(offsetOf(text, 0, 0)).toBeNull();
    expect(offsetOf(text, 1.5, 1)).toBeNull();
  });
});
