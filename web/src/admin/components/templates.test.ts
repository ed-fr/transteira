import { describe, expect, it, vi } from 'vitest';
import { checkTemplate, type TemplateParts } from '../forms/template';
import {
  groupTemplates,
  insertIntoPart,
  issueByPart,
  issueOffset,
  neutralizePreview,
  partFieldId,
  partLabelKey,
  partOfField,
  partsDiffer,
  partsOf,
  previewBody,
  previewHeadingLevel,
  templateIssues,
  type EmailTemplateSummary,
  type PreviewElement,
  type TemplateIssue,
} from './templates';

const parts: TemplateParts = {
  subject: 'Files from {{sender_email}}',
  bodyHtml: '<p>Hello</p>\n<p><a href="{{download_link}}">Download</a></p>',
  bodyText: 'Hello\n{{download_link}}',
};

describe('part names', () => {
  it('maps each part to its translation key and field id', () => {
    expect(partLabelKey('subject')).toBe('adminTenants.templates.part.subject');
    expect(partLabelKey('bodyHtml')).toBe('adminTenants.templates.part.html');
    expect(partLabelKey('bodyText')).toBe('adminTenants.templates.part.text');
    expect(partFieldId('tpl', 'bodyHtml')).toBe('tpl-bodyHtml');
  });
});

describe('groupTemplates', () => {
  const list: EmailTemplateSummary[] = [
    { key: 'verification-code', language: 'en', customised: false },
    { key: 'verification-code', language: 'fr', customised: true, updatedAt: '2026-10-02T10:00:00Z' },
    { key: 'invitation', language: 'fr', customised: false },
  ];

  it('groups by key in API order with one column per language', () => {
    const grid = groupTemplates(list);
    expect(grid.languages).toEqual(['en', 'fr']);
    expect(grid.rows.map((r) => r.key)).toEqual(['verification-code', 'invitation']);
    expect(grid.rows[0]?.cells['fr']?.customised).toBe(true);
    expect(grid.rows[1]?.cells['en']).toBeUndefined();
  });

  it('puts the preferred languages first, ignoring those not listed', () => {
    expect(groupTemplates(list, ['fr', 'de', 'fr']).languages).toEqual(['fr', 'en']);
  });

  it('handles an empty list', () => {
    expect(groupTemplates([])).toEqual({ languages: [], rows: [] });
  });
});

describe('partsDiffer and partsOf', () => {
  it('detects a change in any part', () => {
    expect(partsDiffer(parts, { ...parts })).toBe(false);
    expect(partsDiffer(parts, { ...parts, bodyText: 'x' })).toBe(true);
  });

  it('keeps only the editable parts', () => {
    const tpl = { ...parts, key: 'invitation', variables: ['a'] };
    expect(partsOf(tpl)).toEqual(parts);
  });
});

describe('insertIntoPart (variable chips)', () => {
  it('inserts at the cursor of the chosen part only', () => {
    const r = insertIntoPart(parts, 'bodyText', 'tenant_name', 5);
    expect(r.parts.bodyText).toBe('Hello{{tenant_name}}\n{{download_link}}');
    expect(r.cursor).toBe(5 + '{{tenant_name}}'.length);
    expect(r.parts.subject).toBe(parts.subject);
    expect(r.parts.bodyHtml).toBe(parts.bodyHtml);
  });

  it('replaces the selection', () => {
    const r = insertIntoPart(parts, 'subject', 'tenant_name', 0, 5);
    expect(r.parts.subject).toBe('{{tenant_name}} from {{sender_email}}');
  });

  it('clears a missing-variable warning once the chip is used in both bodies', () => {
    const base: TemplateParts = { subject: 's', bodyHtml: '<p>a</p>', bodyText: 'a' };
    const vars = ['code', 'tenant_name'];
    expect(checkTemplate(base, vars, ['code']).missing).toHaveLength(2);
    const html = insertIntoPart(base, 'bodyHtml', 'code', 3);
    expect(html.parts.bodyHtml).toBe('<p>{{code}}a</p>');
    const both = insertIntoPart(html.parts, 'bodyText', 'code', 99);
    expect(both.parts.bodyText).toBe('a{{code}}');
    expect(checkTemplate(both.parts, vars, ['code'])).toEqual({ unknown: [], missing: [] });
  });
});

describe('server issues', () => {
  it('names the part of a field', () => {
    expect(partOfField('/subject')).toBe('subject');
    expect(partOfField('bodyHtml')).toBe('bodyHtml');
    expect(partOfField('/bodyText/2')).toBe('bodyText');
    expect(partOfField('bodyText.1')).toBe('bodyText');
    expect(partOfField('/other')).toBeUndefined();
  });

  it('maps problem errors to issues', () => {
    const describe = vi.fn((code: string) => `translated ${code}`);
    const issues = templateIssues(
      [
        { field: '/bodyHtml', code: 'invalid', line: 2, column: 4, message: 'unknown variable' },
        { field: '/subject', code: 'required' },
        { field: '/bodyText', code: 'invalid', line: 0, column: 1.5, message: '' },
      ],
      describe,
    );
    expect(issues).toEqual([
      { part: 'bodyHtml', line: 2, column: 4, message: 'unknown variable', fromServer: true },
      {
        part: 'subject',
        line: undefined,
        column: undefined,
        message: 'translated required',
        fromServer: false,
      },
      {
        part: 'bodyText',
        line: undefined,
        column: undefined,
        message: 'translated invalid',
        fromServer: false,
      },
    ]);
    expect(templateIssues(undefined, describe)).toEqual([]);
  });

  it('keeps the first message of each part', () => {
    const issues: TemplateIssue[] = [
      { part: 'bodyHtml', line: 1, column: 1, message: 'first', fromServer: true },
      { part: 'bodyHtml', line: 2, column: 1, message: 'second', fromServer: true },
      { part: undefined, line: undefined, column: undefined, message: 'other', fromServer: true },
    ];
    expect(issueByPart(issues)).toEqual({ bodyHtml: 'first' });
  });

  it('computes the offset of an issue in the current text', () => {
    const at = (part: TemplateIssue['part'], line?: number, column?: number): TemplateIssue => ({
      part,
      line,
      column,
      message: '',
      fromServer: true,
    });
    expect(issueOffset(parts, at('bodyHtml', 2, 4))).toBe('<p>Hello</p>\n'.length + 3);
    expect(issueOffset(parts, at('bodyText', 2))).toBe('Hello\n'.length);
    expect(issueOffset(parts, at('bodyText'))).toBeNull();
    expect(issueOffset(parts, at(undefined, 1, 1))).toBeNull();
  });
});

describe('previewBody', () => {
  it('extracts the content of the body', () => {
    const html =
      '<!DOCTYPE html>\n<html><head><title>T</title></head>\n<body class="x">\n<p>Hi</p>\n</body>\n</html>';
    expect(previewBody(html)).toBe('\n<p>Hi</p>\n');
  });

  it('returns a fragment unchanged', () => {
    expect(previewBody('<p>Hi</p>')).toBe('<p>Hi</p>');
  });
});

describe('neutralizePreview', () => {
  function element(tagName = 'P'): PreviewElement & { attrs: Map<string, string> } {
    const attrs = new Map<string, string>([
      ['href', 'https://example.com'],
      ['target', '_blank'],
      ['role', 'main'],
      ['id', 'x'],
      ['tabindex', '0'],
    ]);
    return {
      tagName,
      attrs,
      removeAttribute: (n) => void attrs.delete(n),
      setAttribute: (n, v) => void attrs.set(n, v),
    };
  }

  it('makes links inert, removes roles, ids and tabindex and nests the headings', () => {
    const link = element('A');
    const main = element('DIV');
    const h1 = element('H1');
    const h2 = element('H2');
    const selectors: string[] = [];
    neutralizePreview(
      {
        querySelectorAll: (selector) => {
          selectors.push(selector);
          if (selector.startsWith('a')) {
            return [link];
          }
          return selector.startsWith('h') ? [h1, h2] : [main];
        },
      },
      'disabled in preview',
      3,
    );
    expect(selectors).toEqual(['a, area', '[role], [id], [tabindex]', 'h1, h2, h3, h4, h5, h6']);
    expect(link.attrs.has('href')).toBe(false);
    expect(link.attrs.has('target')).toBe(false);
    expect(link.attrs.get('title')).toBe('disabled in preview');
    expect([...main.attrs.keys()]).toEqual(['href', 'target']);
    expect(h1.attrs.get('role')).toBe('heading');
    expect(h1.attrs.get('aria-level')).toBe('4');
    expect(h2.attrs.get('aria-level')).toBe('5');
  });
});

describe('previewHeadingLevel', () => {
  it('nests the email headings below the parent level, capped at 6', () => {
    expect(previewHeadingLevel('H1', 3)).toBe(4);
    expect(previewHeadingLevel('h2', 3)).toBe(5);
    expect(previewHeadingLevel('H3', 3)).toBe(6);
    expect(previewHeadingLevel('H6', 4)).toBe(6);
  });
});
