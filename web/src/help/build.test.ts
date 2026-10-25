import { describe, expect, it } from 'vitest';
import {
  GUIDE_IDS,
  HelpBuildError,
  assertNoErrors,
  buildHelp,
  TOPIC_PATTERN,
  forbiddenCharacter,
  formatError,
  generateModule,
  inlineText,
  moduleFileName,
  parseGuide,
  parseInline,
  parseManifest,
  pngSize,
  slugify,
  type GuideSource,
  type ParseOptions,
} from './build';
import { HELP_TOPIC } from '../shared/components/helpers';
import type { GuideId, HelpGuideSet, HelpInline } from './types';

const manifest = new Set(['deposit-form', 'download', 'admin-system']);

function parse(source: string, options: Partial<ParseOptions> = {}) {
  return parseGuide(source, { file: 'g.md', id: 'depositor', lang: 'en', manifest, ...options });
}

function messages(source: string, options: Partial<ParseOptions> = {}): string[] {
  return parse(source, options).errors.map((e) => `${e.line}: ${e.message}`);
}

function inline(text: string): { nodes: HelpInline[]; errors: string[] } {
  const errors: string[] = [];
  const nodes = parseInline(text, (m) => errors.push(m), []);
  return { nodes, errors };
}

describe('slugify', () => {
  it('builds GitHub-compatible anchors', () => {
    expect(slugify('Créer une entité')).toBe('créer-une-entité');
    expect(slugify(' Mail server (SMTP) ')).toBe('mail-server-smtp');
    expect(slugify('Jetons d’API : création')).toBe('jetons-dapi--création');
    expect(slugify('snake_case and-hyphen')).toBe('snake_case-and-hyphen');
  });
});

describe('parseInline', () => {
  it('parses text, bold, italic, code and internal links', () => {
    const { nodes, errors } = inline(
      'A **bold _and_ more**, *it*, `x < y`, [sec](#a-b) and [other](topic:tenant-smtp).',
    );
    expect(errors).toEqual([]);
    expect(nodes).toEqual([
      { type: 'text', text: 'A ' },
      {
        type: 'strong',
        children: [
          { type: 'text', text: 'bold ' },
          { type: 'em', children: [{ type: 'text', text: 'and' }] },
          { type: 'text', text: ' more' },
        ],
      },
      { type: 'text', text: ', ' },
      { type: 'em', children: [{ type: 'text', text: 'it' }] },
      { type: 'text', text: ', ' },
      { type: 'code', text: 'x < y' },
      { type: 'text', text: ', ' },
      { type: 'anchor', target: 'a-b', children: [{ type: 'text', text: 'sec' }] },
      { type: 'text', text: ' and ' },
      { type: 'topic', topic: 'tenant-smtp', children: [{ type: 'text', text: 'other' }] },
      { type: 'text', text: '.' },
    ]);
  });

  it('keeps literal characters: escapes, snake_case, lone stars, brackets, comparisons', () => {
    const { nodes, errors } = inline(
      '\\*not\\* MAX_FILE_SIZE, 2 * 3, [V1.1] [x] a < b & c, ``a`b``, ` padded `',
    );
    expect(errors).toEqual([]);
    expect(inlineText(nodes)).toBe('*not* MAX_FILE_SIZE, 2 * 3, [V1.1] [x] a < b & c, a`b, padded');
  });

  it.each([
    ['`open', 'unclosed code span'],
    ['**open', 'unclosed bold'],
    ['****', 'empty bold'],
    ['*open', 'unclosed italic'],
    ['~~gone~~', 'strikethrough'],
    ['see ![x](../screenshots/en/download.png)', 'images must be alone on their line'],
    ['<b>bold</b>', 'HTML is not supported'],
    ['a &amp; b', 'HTML entities'],
    ['go to https://example.com', 'external URLs'],
    ['go to www.example.com', 'external URLs'],
    ['[site](https://example.com)', 'only internal links'],
    ['[file](other.md)', 'only internal links'],
    ['[x](topic:Bad_Topic)', 'invalid topic'],
    ['[](#a)', 'a link needs a text'],
    ['[a [b](#c)](#d)', 'links cannot be nested'],
  ])('reports %s', (text, message) => {
    expect(inline(text).errors.join('\n')).toContain(message);
  });

  it('refuses links where they are not allowed', () => {
    const errors: string[] = [];
    parseInline('[a](#b)', (m) => errors.push(m), null);
    expect(errors).toEqual(['headings are plain text (no formatting or link)']);
  });
});

const VALID = `# Sender guide

Intro with a [link](#sending-files).

<!-- topic: deposit -->
## Sending files

1. First step
   continued here.
2. Second step
lazily continued.

- bullet one
* bullet two

> **Note:** a note
> on two lines.

![The form](../screenshots/en/deposit-form.png "The sending form")

### Details

Text.

### Details

Again.
`;

describe('parseGuide', () => {
  it('parses a valid guide', () => {
    const result = parse(VALID);
    expect(result.errors).toEqual([]);
    const { guide } = result;
    expect(guide.title).toBe('Sender guide');
    expect(guide.sections.map((s) => [s.level, s.id, s.topic])).toEqual([
      [1, 'sender-guide', 'depositor'],
      [2, 'sending-files', 'deposit'],
      [3, 'details', undefined],
      [3, 'details-1', undefined],
    ]);
    const blocks = guide.sections[1]?.blocks ?? [];
    expect(blocks.map((b) => b.type)).toEqual(['list', 'list', 'note', 'figure']);
    expect(blocks[0]).toEqual({
      type: 'list',
      ordered: true,
      items: [
        [{ type: 'text', text: 'First step continued here.' }],
        [{ type: 'text', text: 'Second step lazily continued.' }],
      ],
    });
    expect(blocks[1]).toMatchObject({ type: 'list', ordered: false });
    expect(blocks[2]).toEqual({
      type: 'note',
      label: 'Note',
      content: [{ type: 'text', text: 'a note on two lines.' }],
    });
    expect(blocks[3]).toEqual({
      type: 'figure',
      src: 'en/deposit-form.png',
      alt: 'The form',
      caption: 'The sending form',
    });
    expect(result.links).toEqual([{ kind: 'anchor', target: 'sending-files', line: 3 }]);
    expect(result.topicLines).toEqual(
      new Map([
        ['depositor', 1],
        ['deposit', 5],
      ]),
    );
  });

  it('accepts CRLF line endings and a figure without caption', () => {
    const result = parse('# T\r\n\r\n![Alt](../screenshots/en/download.png)\r\n');
    expect(result.errors).toEqual([]);
    expect(result.guide.sections[0]?.blocks).toEqual([
      { type: 'figure', src: 'en/download.png', alt: 'Alt' },
    ]);
  });

  it.each([
    ['#### Deep', 'level 4 headings are not supported'],
    ['# T\n\n#### Deep', 'level 4 headings'],
    ['## No title', 'a guide starts with a level 1 heading'],
    ['Text first\n\n# T', 'content before the guide title'],
    ['# T\n\n# Again', 'only one level 1 heading'],
    ['# T\n\n### Skip', 'heading level skipped'],
    ['# T\n\n## **Bold** title', 'headings are plain text'],
    ['# T\n\n## [Link](#t)', 'headings are plain text'],
    ['# T\n\n##', 'empty heading'],
    ['<!-- topic: x -->\n# T', 'the guide title already has the topic'],
    ['# T\n\n<!-- topic: x -->\n\n## A', 'a topic marker must be followed directly by a heading'],
    ['# T\n\n<!-- topic: x -->', 'a topic marker must be followed directly by a heading'],
    ['# T\n\n<!-- topic: Bad -->\n## A', 'invalid topic "Bad"'],
    ['# T\n\n<!-- topic: a -->\n## A\n\n<!-- topic: a -->\n## B', 'duplicate topic "a"'],
    ['# T\n\n<!-- a comment -->', 'HTML is not supported'],
    ['# T\n\n<div>x</div>', 'HTML is not supported'],
    ['# T\n\n```\ncode\n```\n\nafter', 'code blocks are not supported'],
    ['# T\n\n    indented code', 'indented code blocks'],
    ['# T\n\n| a | b |', 'tables are not supported'],
    ['# T\n\n---', 'horizontal rules'],
    ['# T\n\nText\n===', 'horizontal rules and underlined headings'],
    ['# T\n\n- a\n  - nested', 'nested lists are not supported'],
    ['# T\n\n>> nested', 'nested quotes'],
    ['# T\n\n> plain quote', 'a quote is a note starting with a bold label'],
    ['# T\n\n> **Note** text\n> - item', 'a note only holds text'],
    ['# T\n\n![](../screenshots/en/download.png)', 'an image needs an alternative text'],
    ['# T\n\n![Alt](https://example.com/x.png)', 'images are screenshots'],
    ['# T\n\n![Alt](../screenshots/fr/download.png)', 'screenshot of another language'],
    ['# T\n\n![Alt](../screenshots/en/unknown.png)', 'is not in docs/user/screenshots/manifest.json'],
    ['# T\n\n![Alt](broken', 'malformed image'],
    ['# T\n\n\tTabbed', 'tabs are not allowed'],
    ['', 'missing guide title'],
  ])('reports %j', (source, message) => {
    expect(messages(source).join('\n')).toContain(message);
  });

  it('locates errors at their line', () => {
    expect(messages('# T\n\nok\n\n| table |')).toEqual(['5: tables are not supported']);
    expect(messages('# T\n\n- item with ~~strike')).toEqual(['3: strikethrough (~~) is not supported']);
  });

  it('checks that the screenshot exists on disk', () => {
    expect(messages('# T\n\n![Alt](../screenshots/en/download.png)', { imageExists: () => false })).toEqual([
      '3: screenshot en/download.png is missing (run make screenshots)',
    ]);
  });

  it('ends paragraphs, lists and notes at a heading', () => {
    const result = parse('# T\npara\n## A\n- item\n## B\n> **Tip** t\n## C');
    expect(result.errors).toEqual([]);
    expect(result.guide.sections.map((s) => s.blocks.map((b) => b.type))).toEqual([
      ['paragraph'],
      ['list'],
      ['note'],
      [],
    ]);
  });
});

function guide(id: GuideId, lang: string, body: string): GuideSource {
  return { lang, id, file: `docs/user/${lang}/${id}.md`, source: `# ${id} ${lang}\n\n${body}\n` };
}

function sources(overrides: Partial<Record<string, string>> = {}): GuideSource[] {
  const defaults: Record<GuideId, string> = {
    depositor: '<!-- topic: deposit -->\n## Deposit\n\nSee [download](topic:download).',
    recipient: '<!-- topic: download -->\n## Download\n\n![Alt](../screenshots/LANG/download.png)',
    'delegated-admin': '<!-- topic: tenant-smtp -->\n## SMTP\n\nSee [above](#smtp).',
    'super-admin': '<!-- topic: tenant-create -->\n## Create\n\n[Back](#create), [SMTP](topic:tenant-smtp)',
  };
  return ['en', 'fr'].flatMap((lang) =>
    GUIDE_IDS.map((id) =>
      guide(id, lang, (overrides[`${lang}/${id}`] ?? defaults[id]).replace('LANG', lang)),
    ),
  );
}

describe('buildHelp', () => {
  it('builds one set per language and application, with the topic index', () => {
    const { sets, errors } = buildHelp(sources(), { manifest });
    expect(errors).toEqual([]);
    expect(sets.map(moduleFileName)).toEqual(['en-public.ts', 'en-admin.ts', 'fr-public.ts', 'fr-admin.ts']);
    const frAdmin = sets[3];
    expect(frAdmin?.guides.map((g) => g.id)).toEqual(['delegated-admin', 'super-admin']);
    expect(frAdmin?.topics).toEqual({
      'delegated-admin': { guide: 'delegated-admin', section: 'delegated-admin-fr' },
      'tenant-smtp': { guide: 'delegated-admin', section: 'smtp' },
      'super-admin': { guide: 'super-admin', section: 'super-admin-fr' },
      'tenant-create': { guide: 'super-admin', section: 'create' },
    });
  });

  it('reports a missing guide', () => {
    const { errors } = buildHelp(
      sources().filter((s) => !(s.lang === 'fr' && s.id === 'recipient')),
      { manifest },
    );
    expect(errors.map(formatError)).toContain('docs/user/fr/recipient.md:1: missing guide');
  });

  it('reports a topic used by two guides', () => {
    const { errors } = buildHelp(sources({ 'en/recipient': '<!-- topic: deposit -->\n## Download' }), {
      manifest,
    });
    expect(errors.map(formatError)).toContain(
      'docs/user/en/recipient.md:3: topic "deposit" is already used in docs/user/en/depositor.md',
    );
  });

  it('reports broken anchors and topic links, and links to the other application', () => {
    const { errors } = buildHelp(
      sources({
        'en/depositor':
          '<!-- topic: deposit -->\n## Deposit\n\n[a](#nowhere) [b](topic:nothing) [c](topic:tenant-smtp)',
      }),
      { manifest },
    );
    expect(errors.map((e) => e.message)).toEqual([
      'broken link #nowhere: no section with this id in the guide',
      'broken link topic:nothing: unknown topic',
      'link topic:tenant-smtp points to a guide of the other application (delegated-admin)',
    ]);
    expect(errors.every((e) => e.file === 'docs/user/en/depositor.md' && e.line === 6)).toBe(true);
  });

  it('reports topics that differ between languages', () => {
    const { errors } = buildHelp(
      sources({
        'fr/super-admin': '<!-- topic: tenant-create -->\n## Create\n\n<!-- topic: extra -->\n## Extra',
      }),
      { manifest },
    );
    expect(errors.map(formatError)).toEqual([
      'docs/user/en/super-admin.md:1: topic "extra" of docs/user/fr/super-admin.md is missing in this language',
    ]);
  });

  it('passes the parse errors and the image check through', () => {
    const { errors } = buildHelp(sources(), { manifest, imageExists: (lang) => lang === 'en' });
    expect(errors.map(formatError)).toEqual([
      'docs/user/fr/recipient.md:6: screenshot fr/download.png is missing (run make screenshots)',
    ]);
  });
});

describe('assertNoErrors', () => {
  it('throws every error at once', () => {
    expect(() => assertNoErrors([])).not.toThrow();
    const error = { file: 'a.md', line: 2, message: 'bad' };
    expect(() => assertNoErrors([error])).toThrow(HelpBuildError);
    try {
      assertNoErrors([error]);
    } catch (err) {
      expect((err as HelpBuildError).errors).toEqual([error]);
      expect((err as Error).message).toContain('a.md:2: bad');
    }
  });
});

/**
 * Evaluates a generated module: its imports become parameters (the URL of each screenshot) and
 * its data part is run as an expression, so that the test sees exactly what the browser gets.
 */
function evaluate(code: string, urls: Record<string, string>): HelpGuideSet {
  const imports = [...code.matchAll(/^import (image\d+) from (".*");$/gm)].map(
    ([, name, path]) => [name as string, JSON.parse(path as string) as string] as const,
  );
  const start = code.indexOf('const guides: HelpGuideSet = ') + 'const guides: HelpGuideSet = '.length;
  const end = code.lastIndexOf(';\n\nexport default guides;');
  // A test-only evaluation in Node (the CSP rule against new Function is about the browser).
  // eslint-disable-next-line no-restricted-syntax
  const build = new Function(...imports.map(([name]) => name), `return (${code.slice(start, end)});`) as (
    ...args: string[]
  ) => HelpGuideSet;
  return build(...imports.map(([, path]) => urls[path] ?? `missing:${path}`));
}

describe('generateModule', () => {
  it('imports each screenshot once and references it from the figures', () => {
    const { sets } = buildHelp(
      sources({
        'en/recipient':
          '<!-- topic: download -->\n## Download\n\n![A](../screenshots/en/download.png)\n\n![B](../screenshots/en/download.png)\n\n![C](../screenshots/en/deposit-form.png)',
      }),
      { manifest },
    );
    const set = sets[0] as HelpGuideSet;
    const code = generateModule(set, '../../shots');
    expect(code).toContain("import type { HelpGuideSet } from '../types';");
    expect(code.match(/^import image\d+ from .*$/gm)).toEqual([
      'import image0 from "../../shots/en/download.png";',
      'import image1 from "../../shots/en/deposit-form.png";',
    ]);
    expect(code.match(/"src": image\d+/g)).toEqual(['"src": image0', '"src": image0', '"src": image1']);
    expect(code).toContain('export default guides;');
    const loaded = evaluate(code, {
      '../../shots/en/download.png': '/assets/download-1.png',
      '../../shots/en/deposit-form.png': '/assets/deposit-form-2.png',
    });
    const figures = loaded.guides
      .flatMap((g) => g.sections.flatMap((s) => s.blocks))
      .filter((b) => b.type === 'figure');
    expect(figures.map((f) => [f.alt, f.src])).toEqual([
      ['A', '/assets/download-1.png'],
      ['B', '/assets/download-1.png'],
      ['C', '/assets/deposit-form-2.png'],
    ]);
    expect(loaded.topics).toEqual(set.topics);
  });

  it('writes hostile text as data, never as code', () => {
    const hostile = [
      `' " \\ \` \${x} */ </script> /* //`,
      'line\u2028separator\u2029paragraph',
      '"\\u0000IMG0\\u0000" \u0000IMG0\u0000 image1 image0',
      '"; throw new Error("injected"); "',
    ];
    const set: HelpGuideSet = {
      lang: 'en',
      app: 'public',
      guides: [
        {
          id: 'depositor',
          title: hostile[0] as string,
          sections: [
            {
              id: 'image1',
              level: 1,
              title: 'image0',
              topic: 'depositor',
              blocks: [
                ...hostile.map((text) => ({
                  type: 'paragraph' as const,
                  content: [{ type: 'text' as const, text }],
                })),
                {
                  type: 'figure',
                  src: 'en/download.png',
                  alt: hostile[2] as string,
                  caption: 'image1',
                  width: 2,
                  height: 1,
                },
                {
                  type: 'note',
                  label: hostile[1] as string,
                  content: [{ type: 'code', text: hostile[3] as string }],
                },
              ],
            },
          ],
        },
      ],
      topics: { depositor: { guide: 'depositor', section: 'image1' } },
    };
    const code = generateModule(set, '../shots');
    expect(code).not.toMatch(/[\u2028\u2029]/);
    expect(code.match(/^import .*$/gm)).toEqual([
      "import type { HelpGuideSet } from '../types';",
      'import image0 from "../shots/en/download.png";',
    ]);
    const loaded = evaluate(code, { '../shots/en/download.png': '/assets/download.png' });
    const blocks = set.guides[0]?.sections[0]?.blocks ?? [];
    const expected = structuredClone(set);
    const figure = expected.guides[0]?.sections[0]?.blocks[blocks.length - 2];
    if (figure?.type === 'figure') figure.src = '/assets/download.png';
    expect(loaded).toEqual(expected);
  });
});

describe('forbiddenCharacter', () => {
  it.each([
    [0x00, 'U+0000'],
    [0x08, 'U+0008'],
    [0x0b, 'U+000B'],
    [0x0c, 'U+000C'],
    [0x1f, 'U+001F'],
    [0x7f, 'U+007F'],
    [0x2028, 'U+2028'],
    [0x2029, 'U+2029'],
    [0x202a, 'U+202A'],
    [0x202e, 'U+202E'],
    [0x2066, 'U+2066'],
    [0x2069, 'U+2069'],
  ])('reports %d', (code, expected) => {
    expect(forbiddenCharacter(`ok ${String.fromCodePoint(code)} ok`)).toBe(expected);
  });

  it('accepts tabs, accents, typographic characters and emoji', () => {
    expect(forbiddenCharacter('\tCréer l’entité « A » – 80 % 😀 ‍  ')).toBeUndefined();
  });

  it('fails the guide at the line of the character', () => {
    const rlo = String.fromCodePoint(0x202e);
    expect(messages(`# T\n\nfine\nsee ${rlo}gnp.exe`)).toEqual([
      '4: control or bidirectional formatting character U+202E is not allowed',
    ]);
    expect(messages(`# T\n\n- a${String.fromCodePoint(0x2028)}b`)).toEqual([
      '3: control or bidirectional formatting character U+2028 is not allowed',
    ]);
  });
});

describe('pngSize', () => {
  const header = (width: number, height: number, chunk = 'IHDR'): Uint8Array => {
    const bytes = new Uint8Array(24);
    bytes.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13]);
    bytes.set(
      [...chunk].map((c) => c.charCodeAt(0)),
      12,
    );
    const view = new DataView(bytes.buffer);
    view.setUint32(16, width);
    view.setUint32(20, height);
    return bytes;
  };

  it('reads the size from the IHDR chunk', () => {
    expect(pngSize(header(1280, 800))).toEqual({ width: 1280, height: 800 });
    const offset = new Uint8Array(30);
    offset.set(header(3, 2), 6);
    expect(pngSize(offset.subarray(6))).toEqual({ width: 3, height: 2 });
  });

  it('refuses what is not a PNG', () => {
    expect(pngSize(new Uint8Array(10))).toBeUndefined();
    expect(pngSize(new TextEncoder().encode('GIF89a and a long enough tail'))).toBeUndefined();
    expect(pngSize(header(10, 10, 'IDAT'))).toBeUndefined();
    expect(pngSize(header(0, 10))).toBeUndefined();
  });

  it('gives the figures their size, and reports an invalid image', () => {
    const size = (_lang: string, name: string) => (name === 'download' ? { width: 4, height: 3 } : undefined);
    const ok = parse('# T\n\n![Alt](../screenshots/en/download.png)', { imageSize: size });
    expect(ok.guide.sections[0]?.blocks).toEqual([
      { type: 'figure', src: 'en/download.png', alt: 'Alt', width: 4, height: 3 },
    ]);
    expect(messages('# T\n\n![Alt](../screenshots/en/deposit-form.png)', { imageSize: size })).toEqual([
      '3: screenshot en/deposit-form.png is not a valid PNG image',
    ]);
  });
});

describe('parseManifest', () => {
  const file = 'docs/user/screenshots/manifest.json';

  it('returns the screenshot names', () => {
    const { names, errors } = parseManifest(
      '[{"name":"deposit-form","route":"/"},{"name":"download"}]',
      file,
    );
    expect(errors).toEqual([]);
    expect([...names]).toEqual(['deposit-form', 'download']);
  });

  it('locates a JSON syntax error', () => {
    const { errors } = parseManifest('[\n  {"name": "a"},\n  {"name" "b"}\n]', file);
    expect(errors).toHaveLength(1);
    expect(errors[0]?.file).toBe(file);
    expect(errors[0]?.line).toBe(3);
    expect(errors[0]?.message).toMatch(/^invalid JSON: /);
    // Without a location in the message, the error is on line 1.
    expect(parseManifest('[1,', file).errors.map((e) => e.line)).toEqual([1]);
  });

  it('reports an unexpected shape', () => {
    expect(parseManifest('{"name":"a"}', file).errors.map(formatError)).toEqual([
      `${file}:1: the manifest must be an array of {"name": …}`,
    ]);
    expect(
      parseManifest('[{"name":"ok"},{"name":"Bad Name"},null,{}]', file).errors.map((e) => e.message),
    ).toEqual([
      'entry 1: "name" must be a lower-case slug',
      'entry 2: "name" must be a lower-case slug',
      'entry 3: "name" must be a lower-case slug',
    ]);
  });
});

describe('GitHub compatibility', () => {
  it('keeps the topic pattern in sync with HELP_TOPIC', () => {
    expect(TOPIC_PATTERN.source).toBe(HELP_TOPIC.source);
  });

  it('gives unique section ids, like GitHub', () => {
    const result = parse('# T\n\n## Foo\n\n## Foo\n\n## Foo 1\n\n## Foo');
    expect(result.errors).toEqual([]);
    expect(result.guide.sections.map((s) => s.id)).toEqual(['t', 'foo', 'foo-1', 'foo-1-1', 'foo-2']);
  });

  it('reads __bold__ as bold, and leaves snake__case alone', () => {
    const { nodes, errors } = inline('__bold__, a__b__c and __a _b_ c__');
    expect(errors).toEqual([]);
    expect(nodes).toEqual([
      { type: 'strong', children: [{ type: 'text', text: 'bold' }] },
      { type: 'text', text: ', a__b__c and ' },
      {
        type: 'strong',
        children: [
          { type: 'text', text: 'a ' },
          { type: 'em', children: [{ type: 'text', text: 'b' }] },
          { type: 'text', text: ' c' },
        ],
      },
    ]);
    expect(inline('__open').errors).toEqual(['unclosed bold (__)']);
  });

  it('drops the closing hashes of a heading', () => {
    const result = parse('# Title #\n\n## Mail (SMTP) ##\n\n## C#\n\n## Sharp \\#');
    expect(result.errors).toEqual([]);
    expect(result.guide.sections.map((s) => s.title)).toEqual(['Title', 'Mail (SMTP)', 'C#', 'Sharp #']);
    expect(messages('# T\n\n## ##')).toEqual(['3: empty heading']);
  });

  it.each([
    ['# T\n\na | b\n--|--\n1 | 2', '4: tables are not supported'],
    ['# T\n\na | b\n:-- | --:', '4: tables are not supported'],
    [
      '# T\n\n- item\n\n  continued',
      '5: a list item cannot continue after a blank line (remove the blank line)',
    ],
    [
      '# T\n\n1. one\n\n    continued',
      '5: a list item cannot continue after a blank line (remove the blank line)',
    ],
    ['# T\n\n1. one\n\n2. two', '5: list items cannot be separated by a blank line (remove the blank line)'],
    ['# T\n\n> **Note** one\n>\n> two', '4: a note is a single paragraph: remove the empty ">" line'],
  ])('refuses %j', (source, message) => {
    expect(messages(source)).toEqual([message]);
  });

  it('accepts what reads the same on GitHub', () => {
    const result = parse(
      '# T\n\n- item\n\nAfter the list | with a pipe.\n\n1. a\n\n- b\n\n> **Tip** a\nlazy',
    );
    expect(result.errors.map(formatError)).toEqual([]);
    expect(result.guide.sections[0]?.blocks.at(-1)).toEqual({
      type: 'note',
      label: 'Tip',
      content: [{ type: 'text', text: 'a lazy' }],
    });
  });
});

describe('error lines inside joined blocks', () => {
  it('locates inline errors at their own line', () => {
    expect(messages('# T\n\nfirst line\nsecond ~~x line\nthird `open')).toEqual([
      '4: strikethrough (~~) is not supported',
      '5: unclosed code span (`)',
    ]);
    expect(messages('# T\n\n- item\n  continued <b>\n- next')).toEqual([
      '4: HTML is not supported (only topic markers <!-- topic: … -->)',
    ]);
    expect(messages('# T\n\n> **Note** text\n> more https://example.com')).toEqual([
      '4: external URLs are not allowed (write paths and addresses as `code`)',
    ]);
  });

  it('locates links at their own line', () => {
    const result = parse('# T\n\nintro\nsee [x](#t)\nand [y](topic:other)');
    expect(result.links).toEqual([
      { kind: 'anchor', target: 't', line: 4 },
      { kind: 'topic', target: 'other', line: 5 },
    ]);
  });
});

describe('buildHelp audience checks', () => {
  it('refuses a topic link from the delegated-admin guide to the super-admin guide', () => {
    const { errors } = buildHelp(
      sources({
        'en/delegated-admin': '<!-- topic: tenant-smtp -->\n## SMTP\n\nSee [create](topic:tenant-create).',
      }),
      { manifest },
    );
    expect(errors.map(formatError)).toEqual([
      'docs/user/en/delegated-admin.md:6: link topic:tenant-create points to the super-admin guide, which a delegated admin cannot read',
    ]);
  });

  it('reports a missing guide once', () => {
    const { errors } = buildHelp(
      sources().filter((s) => !(s.lang === 'en' && s.id === 'depositor')),
      { manifest },
    );
    expect(errors.filter((e) => e.message === 'missing guide').map(formatError)).toEqual([
      'docs/user/en/depositor.md:1: missing guide',
    ]);
  });

  it('passes the image size through', () => {
    const { sets } = buildHelp(sources(), { manifest, imageSize: () => ({ width: 8, height: 5 }) });
    const figure = sets[0]?.guides[1]?.sections[1]?.blocks[0];
    expect(figure).toMatchObject({ type: 'figure', width: 8, height: 5 });
  });
});
