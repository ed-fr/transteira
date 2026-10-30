// Conversion of the user guides (docs/user/<lang>/<guide>.md) into the data of the integrated
// help (CLAUDE.md section 4.2). Pure functions, no I/O: scripts/build-help.mjs reads the files,
// calls buildHelp and writes the modules returned by generateModule. The script runs this file
// directly with Node (type stripping), so it only uses erasable TypeScript syntax and imports
// nothing at runtime.
//
// Accepted Markdown subset (anything else fails the build with file:line errors, so that a guide
// reads the same on GitHub and in the application, and never needs HTML):
//   - one level 1 heading first (the guide title), then level 2 and 3 headings, without skipping
//     a level; headings are plain text (closing hashes "## Title ##" are dropped, like on GitHub);
//   - paragraphs; bullet ("-", "*" or "+") and numbered ("1." or "1)") lists, one level, an item
//     may continue on the following lines (never after a blank line);
//   - inline: **bold** or __bold__, *italic* or _italic_, `code`, backslash escapes, and internal
//     links only:
//     [text](#section-id) to a section of the same guide, [text](topic:some-topic) to a help topic
//     of the same application;
//   - screenshots alone on their line: ![alt text](../screenshots/<lang>/<name>.png "caption"),
//     alt text required, caption optional, image listed in the screenshots manifest;
//   - notes: "> **Label** text", the following "> " lines continuing the note (one paragraph: an
//     empty ">" line is refused);
//   - topic markers: "<!-- topic: some-topic -->" on the line right before a level 2 or 3
//     heading. Each guide also has an implicit topic, its id, on its title. "print" is reserved
//     (printable page /help/print);
//   - feature markers (public guides only): "<!-- when: <feature> -->" on the line(s) right before
//     a level 2 or 3 heading, in either order with a topic marker (each at most once), hides the
//     section and its sub-sections for a tenant whose feature is off (HelpFeature);
//   - rules markers (public guides only): "<!-- rules: <set> -->" alone on its line, set being
//     summary, limits or levels, renders the real rules of the tenant at this place (RulesSet).
// Refused: other headings levels, tables (with or without outer pipes), code blocks, horizontal
// rules, nested lists or quotes, list items separated or continued after a blank line, HTML
// (other than the topic, when and rules markers), entities, strikethrough, inline images, external or relative links,
// bare URLs, control characters and bidirectional formatting characters (invisible in a review).
import type {
  GuideId,
  HelpApp,
  HelpBlock,
  HelpFeature,
  HelpGuide,
  HelpGuideSet,
  HelpInline,
  HelpSection,
  RulesSet,
} from './types';

/** Languages of the guides (same as the interface). */
export const HELP_LANGUAGES: readonly string[] = ['en', 'fr'];

/** Guides in display order. */
export const GUIDE_IDS: readonly GuideId[] = ['depositor', 'recipient', 'delegated-admin', 'super-admin'];

/** Application showing each guide. */
export const GUIDE_APPS: Readonly<Record<GuideId, HelpApp>> = {
  depositor: 'public',
  recipient: 'public',
  'delegated-admin': 'admin',
  'super-admin': 'admin',
};

/** Pattern of a help topic (same as HELP_TOPIC of shared/components/helpers.ts). */
export const TOPIC_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

/** Topics that cannot be used in the guides. */
export const RESERVED_TOPICS: readonly string[] = ['print'];

/** Values accepted by "<!-- rules: … -->". */
export const RULES_SETS: readonly RulesSet[] = ['summary', 'limits', 'levels'];

/** Values accepted by "<!-- when: … -->". */
export const HELP_FEATURES: readonly HelpFeature[] = [
  'remoteInternalDeposit',
  'transferReply',
  'recipientVerification',
  'maxDownloads',
  'folders',
];

/** A build error, located in a guide. */
export interface HelpError {
  file: string;
  line: number;
  message: string;
}

/** Thrown by assertNoErrors with every error found. */
export class HelpBuildError extends Error {
  readonly errors: HelpError[];

  constructor(errors: HelpError[]) {
    super(`integrated help: ${errors.length} error(s)\n${errors.map(formatError).join('\n')}`);
    this.name = 'HelpBuildError';
    this.errors = errors;
  }
}

/** Formats an error as "file:line: message". */
export function formatError(error: HelpError): string {
  return `${error.file}:${error.line}: ${error.message}`;
}

/** Throws a HelpBuildError when errors is not empty. */
export function assertNoErrors(errors: readonly HelpError[]): void {
  if (errors.length > 0) {
    throw new HelpBuildError([...errors]);
  }
}

/**
 * Returns the GitHub-compatible anchor of a heading: lower case, punctuation removed (letters,
 * digits, spaces, hyphens and underscores kept, accents included), spaces turned into hyphens.
 */
export function slugify(text: string): string {
  return text
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{M}\p{N} _-]/gu, '')
    .replace(/ /g, '-');
}

/**
 * Returns the first forbidden character of a line as "U+XXXX": C0 controls other than the tab,
 * DEL, the Unicode line and paragraph separators, and the bidirectional embedding, override and
 * isolate characters (U+202A to U+202E, U+2066 to U+2069), which are invisible in a review and
 * can make a text read differently from what it says (threat model T-91).
 */
export function forbiddenCharacter(line: string): string | undefined {
  for (const char of line) {
    const code = char.codePointAt(0) as number;
    if (
      (code < 0x20 && code !== 0x09) ||
      code === 0x7f ||
      code === 0x2028 ||
      code === 0x2029 ||
      (code >= 0x202a && code <= 0x202e) ||
      (code >= 0x2066 && code <= 0x2069)
    ) {
      return `U+${code.toString(16).toUpperCase().padStart(4, '0')}`;
    }
  }
  return undefined;
}

/**
 * Returns the width and height of a PNG image from its first bytes (signature and IHDR chunk), or
 * undefined when the bytes are not a PNG.
 */
export function pngSize(bytes: Uint8Array): { width: number; height: number } | undefined {
  const signature = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (bytes.length < 24 || signature.some((byte, i) => bytes[i] !== byte)) {
    return undefined;
  }
  const ihdr = String.fromCharCode(...bytes.subarray(12, 16));
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const width = view.getUint32(16);
  const height = view.getUint32(20);
  if (ihdr !== 'IHDR' || width === 0 || height === 0) {
    return undefined;
  }
  return { width, height };
}

/**
 * Parses docs/user/screenshots/manifest.json (an array of {name}) into the set of screenshot
 * names; a syntax error or an unexpected shape is returned as an error located in file.
 */
export function parseManifest(text: string, file: string): { names: Set<string>; errors: HelpError[] } {
  const names = new Set<string>();
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch (err) {
    // JSON.parse throws a SyntaxError whose message carries "(line N column M)" when V8 knows it.
    const message = (err as Error).message;
    const line = /line (\d+)/.exec(message);
    return {
      names,
      errors: [{ file, line: line === null ? 1 : Number(line[1]), message: `invalid JSON: ${message}` }],
    };
  }
  if (!Array.isArray(data)) {
    return { names, errors: [{ file, line: 1, message: 'the manifest must be an array of {"name": …}' }] };
  }
  const errors: HelpError[] = [];
  for (const [index, entry] of data.entries()) {
    const name = (entry as { name?: unknown } | null)?.name;
    if (typeof name !== 'string' || !TOPIC_PATTERN.test(name)) {
      errors.push({ file, line: 1, message: `entry ${index}: "name" must be a lower-case slug` });
    } else {
      names.add(name);
    }
  }
  return { names, errors };
}

/** An internal link found in a guide, checked once every guide is parsed. */
export interface LinkRef {
  kind: 'anchor' | 'topic';
  target: string;
  line: number;
}

const PUNCTUATION = /[!-/:-@[-`{-~]/;
const WORD = /[\p{L}\p{N}]/u;

function isWordChar(c: string | undefined): boolean {
  return c !== undefined && WORD.test(c);
}

function isSpace(c: string | undefined): boolean {
  return c === undefined || /\s/.test(c);
}

function mergeText(nodes: HelpInline[]): HelpInline[] {
  const out: HelpInline[] = [];
  for (const node of nodes) {
    const last = out[out.length - 1];
    if (node.type === 'text' && last !== undefined && last.type === 'text') {
      last.text += node.text;
    } else {
      out.push(node);
    }
  }
  return out;
}

type Closer = '**' | '__' | '*' | '_' | ']';

/**
 * Parses the inline content of a block. report is called with each error and the offset in text
 * where the faulty construct starts (the caller adds the location); links, when given, receives
 * the internal links (null: links are refused), located with lineAt(offset).
 */
export function parseInline(
  text: string,
  report: (message: string, offset: number) => void,
  links: LinkRef[] | null,
  lineAt: (offset: number) => number = () => 0,
): HelpInline[] {
  let pos = 0;
  const reportAt = report;

  function atCloser(closer: Closer): boolean {
    switch (closer) {
      case '**':
        return text.startsWith('**', pos);
      case '__':
        return text.startsWith('__', pos) && !isWordChar(text[pos + 2]);
      case '*':
        return text[pos] === '*' && !text.startsWith('**', pos);
      case '_':
        return text[pos] === '_' && text[pos + 1] !== '_' && !isWordChar(text[pos + 1]);
      default:
        return text[pos] === ']';
    }
  }

  function seq(closer: Closer | undefined, inLink: boolean): { nodes: HelpInline[]; closed: boolean } {
    const nodes: HelpInline[] = [];
    let buf = '';
    const flush = (): void => {
      if (buf !== '') {
        nodes.push({ type: 'text', text: buf });
        buf = '';
      }
    };
    while (pos < text.length) {
      if (closer !== undefined && atCloser(closer)) {
        pos += closer.length;
        flush();
        return { nodes: mergeText(nodes), closed: true };
      }
      const start = pos;
      const report = (message: string): void => reportAt(message, start);
      const c = text[pos] as string;
      const next = text[pos + 1];
      const rest = text.slice(pos);
      if (c === '\\' && next !== undefined && PUNCTUATION.test(next)) {
        buf += next;
        pos += 2;
      } else if (c === '`') {
        const run = /^`+/.exec(rest)?.[0] ?? '`';
        const end = text.indexOf(run, pos + run.length);
        if (end === -1) {
          report('unclosed code span (`)');
          buf += run;
          pos += run.length;
          continue;
        }
        flush();
        let code = text.slice(pos + run.length, end);
        if (code.length > 2 && code.startsWith(' ') && code.endsWith(' ')) {
          code = code.slice(1, -1);
        }
        nodes.push({ type: 'code', text: code });
        pos = end + run.length;
      } else if (rest.startsWith('**')) {
        flush();
        pos += 2;
        const inner = seq('**', inLink);
        if (!inner.closed) report('unclosed bold (**)');
        if (inner.nodes.length === 0) report('empty bold (**)');
        nodes.push({ type: 'strong', children: inner.nodes });
      } else if (c === '_' && isWordChar(text[pos - 1])) {
        // Underscores inside a word (snake_case, a__b) are text, like on GitHub.
        const run = /^_+/.exec(rest)?.[0] ?? '_';
        buf += run;
        pos += run.length;
      } else if (rest.startsWith('__') && !isWordChar(text[pos - 1]) && !isSpace(text[pos + 2])) {
        // __bold__, like on GitHub (only at a word boundary, so that snake__case stays text).
        flush();
        pos += 2;
        const inner = seq('__', inLink);
        if (!inner.closed) report('unclosed bold (__)');
        if (inner.nodes.length === 0) report('empty bold (__)');
        nodes.push({ type: 'strong', children: inner.nodes });
      } else if ((c === '*' || (c === '_' && !isWordChar(text[pos - 1]))) && !isSpace(next)) {
        flush();
        pos += 1;
        const inner = seq(c, inLink);
        if (!inner.closed) report(`unclosed italic (${c})`);
        nodes.push({ type: 'em', children: inner.nodes });
      } else if (rest.startsWith('~~')) {
        report('strikethrough (~~) is not supported');
        buf += '~~';
        pos += 2;
      } else if (rest.startsWith('![')) {
        report('images must be alone on their line');
        buf += '!';
        pos += 1;
      } else if (c === '[') {
        flush();
        pos += 1;
        const label = seq(']', true);
        const target = label.closed ? /^\(([^()\s]*)\)/.exec(text.slice(pos)) : null;
        if (target === null) {
          // Not a link: the brackets are plain text (like on GitHub).
          nodes.push({ type: 'text', text: '[' }, ...label.nodes);
          if (label.closed) nodes.push({ type: 'text', text: ']' });
          continue;
        }
        pos += target[0].length;
        const node = linkNode(target[1] as string, label.nodes, inLink, start);
        if (node !== undefined) nodes.push(node);
        else nodes.push(...label.nodes);
      } else if (c === '<' && next !== undefined && /[A-Za-z/!?]/.test(next)) {
        report('HTML is not supported (only the topic, when and rules markers <!-- topic: … -->)');
        buf += c;
        pos += 1;
      } else if (c === '&' && /^&(?:#\d+|#x[0-9a-f]+|[a-z][a-z0-9]*);/i.test(rest)) {
        report('HTML entities are not supported: write the character itself');
        buf += c;
        pos += 1;
      } else if (/^https?:\/\//i.test(rest) || /^www\./i.test(rest)) {
        report('external URLs are not allowed (write paths and addresses as `code`)');
        buf += c;
        pos += 1;
      } else {
        buf += c;
        pos += 1;
      }
    }
    flush();
    return { nodes: mergeText(nodes), closed: false };
  }

  function linkNode(
    target: string,
    children: HelpInline[],
    inLink: boolean,
    start: number,
  ): HelpInline | undefined {
    const report = (message: string): void => reportAt(message, start);
    const line = lineAt(start);
    if (links === null) {
      report('headings are plain text (no formatting or link)');
      return undefined;
    }
    if (inLink) {
      report('links cannot be nested');
      return undefined;
    }
    if (children.length === 0) {
      report('a link needs a text');
    }
    if (target.startsWith('#') && target.length > 1) {
      links.push({ kind: 'anchor', target: target.slice(1), line });
      return { type: 'anchor', target: target.slice(1), children };
    }
    if (target.startsWith('topic:')) {
      const topic = target.slice('topic:'.length);
      if (!TOPIC_PATTERN.test(topic)) {
        report(`invalid topic "${topic}" (lower-case words separated by hyphens)`);
        return undefined;
      }
      links.push({ kind: 'topic', target: topic, line });
      return { type: 'topic', topic, children };
    }
    report(`only internal links are allowed ([text](#section) or [text](topic:some-topic)): "${target}"`);
    return undefined;
  }

  const result = seq(undefined, false);
  return result.nodes;
}

/** Plain text of inline nodes. */
export function inlineText(nodes: readonly HelpInline[]): string {
  return nodes
    .map((node) => (node.type === 'text' || node.type === 'code' ? node.text : inlineText(node.children)))
    .join('');
}

/** Options of parseGuide. */
export interface ParseOptions {
  /** File name used in the errors (e.g. "docs/user/fr/depositor.md"). */
  file: string;
  id: GuideId;
  lang: string;
  /** Names of the screenshots manifest (docs/user/screenshots/manifest.json). */
  manifest: ReadonlySet<string>;
  /** Reports whether the image of a screenshot exists on disk; every image exists by default. */
  imageExists?: (lang: string, name: string) => boolean;
  /**
   * Returns the size of an existing screenshot (undefined: not a valid PNG), written on the figure
   * so that the page does not move while the image loads; without it, figures have no size.
   */
  imageSize?: (lang: string, name: string) => { width: number; height: number } | undefined;
}

/** A parsed guide. Figure src holds the manifest path "<lang>/<name>.png" (see generateModule). */
export interface ParsedGuide {
  guide: HelpGuide;
  /** Line of each topic marker (the implicit guide topic is on line 1). */
  topicLines: Map<string, number>;
  /** Rules markers in document order, with their line (compared between languages). */
  rules: { set: RulesSet; line: number }[];
  /** Internal links, checked by buildHelp. */
  links: LinkRef[];
  /** Index in guide.sections of the section holding each link (parallel to links). */
  linkSections: number[];
  /** Line of the heading of each section (parallel to guide.sections). */
  sectionLines: number[];
  errors: HelpError[];
}

/** A source line of a block whose lines are joined (paragraph, list item, note). */
interface Piece {
  text: string;
  line: number;
}

/**
 * Joins the lines of a block with spaces (empty pieces dropped) and returns the text with a
 * function mapping an offset of this text back to its source line.
 */
function joinPieces(
  pieces: readonly Piece[],
  fallback: number,
): { text: string; lineAt: (offset: number) => number } {
  const starts: { offset: number; line: number }[] = [];
  let text = '';
  for (const piece of pieces) {
    if (piece.text === '') continue;
    if (text !== '') text += ' ';
    starts.push({ offset: text.length, line: piece.line });
    text += piece.text;
  }
  const lineAt = (offset: number): number => {
    let line = starts[0]?.line ?? fallback;
    for (const start of starts) {
      if (start.offset > offset) break;
      line = start.line;
    }
    return line;
  };
  return { text, lineAt };
}

const HEADING = /^(#{1,6})(?:\s+(.*?))?\s*$/;
const CLOSING_HASHES = /(?:^|\s+)#+$/;
const TOPIC_MARKER = /^<!--\s*topic:\s*(.*?)\s*-->$/;
const WHEN_MARKER = /^<!--\s*when:\s*(.*?)\s*-->$/;
const RULES_MARKER = /^<!--\s*rules:\s*(.*?)\s*-->$/;
const BULLET = /^[-*+]\s+(.*)$/;
const ORDERED = /^\d{1,9}[.)]\s+(.*)$/;
const IMAGE = /^!\[([^\]]*)\]\(([^)\s]+)(?:\s+"([^"]*)")?\)$/;
const SCREENSHOT = /^\.\.\/screenshots\/([a-z]{2})\/([a-z0-9]+(?:-[a-z0-9]+)*)\.png$/;
const RULE = /^(?:(?:-\s*){3,}|(?:\*\s*){3,}|(?:_\s*){3,}|=+)$/;
/** Delimiter row of a table, with or without outer pipes ("--|--", "| :-- | --: |"). */
const TABLE_DELIMITER = /^\|?\s*:?-+:?\s*(?:\|\s*:?-+:?\s*)*\|?$/;

/** Parses one guide. Never throws: the errors are returned with the (partial) guide. */
export function parseGuide(source: string, options: ParseOptions): ParsedGuide {
  const { file, id, lang } = options;
  const errors: HelpError[] = [];
  const links: LinkRef[] = [];
  const linkSections: number[] = [];
  const sectionLines: number[] = [];
  const topicLines = new Map<string, number>();
  const rules: { set: RulesSet; line: number }[] = [];
  const sections: HelpSection[] = [];
  const usedIds = new Set<string>();
  const lines = source.replace(/\r\n?/g, '\n').split('\n');

  let lineNo = 0;
  const error = (message: string, at = lineNo): void => {
    errors.push({ file, line: at, message });
  };

  let pendingTopic: { topic: string; line: number } | undefined;
  let pendingWhen: { feature: HelpFeature; line: number } | undefined;
  let para: { pieces: Piece[]; line: number } | undefined;
  let list: { ordered: boolean; items: { pieces: Piece[]; line: number }[] } | undefined;
  let note: { label: string; pieces: Piece[]; line: number } | undefined;
  /** A blank line just ended a list (GitHub would continue the list on an indented line). */
  let afterList: { ordered: boolean } | undefined;

  const inline = (pieces: readonly Piece[], at: number): HelpInline[] => {
    const { text, lineAt } = joinPieces(pieces, at);
    const nodes = parseInline(text, (message, offset) => error(message, lineAt(offset)), links, lineAt);
    while (linkSections.length < links.length) linkSections.push(sections.length - 1);
    return nodes;
  };

  function push(block: HelpBlock, at: number): void {
    const section = sections[sections.length - 1];
    if (section === undefined) {
      error('content before the guide title (level 1 heading)', at);
      return;
    }
    section.blocks.push(block);
  }

  function flush(): void {
    if (para !== undefined) {
      push({ type: 'paragraph', content: inline(para.pieces, para.line) }, para.line);
      para = undefined;
    }
    if (list !== undefined) {
      const items = list.items.map((item) => inline(item.pieces, item.line));
      push({ type: 'list', ordered: list.ordered, items }, list.items[0]?.line ?? lineNo);
      list = undefined;
    }
    if (note !== undefined) {
      push({ type: 'note', label: note.label, content: inline(note.pieces, note.line) }, note.line);
      note = undefined;
    }
  }

  /** Section id: the slug of the title, suffixed -1, -2… until unused (like GitHub). */
  function uniqueId(title: string): string {
    const base = slugify(title) || 'section';
    let candidate = base;
    for (let n = 1; usedIds.has(candidate); n++) {
      candidate = `${base}-${n}`;
    }
    usedIds.add(candidate);
    return candidate;
  }

  function heading(level: number, rawTitle: string): void {
    flush();
    const topic = pendingTopic;
    const when = pendingWhen;
    pendingTopic = undefined;
    pendingWhen = undefined;
    if (level > 3) {
      error(`level ${level} headings are not supported (levels 1 to 3)`);
      return;
    }
    const titleNodes = parseInline(rawTitle.replace(CLOSING_HASHES, ''), (message) => error(message), null);
    if (titleNodes.some((node) => node.type !== 'text')) {
      error('headings are plain text (no formatting or link)');
    }
    const title = inlineText(titleNodes).trim();
    if (title === '') {
      error('empty heading');
    }
    const previous = sections[sections.length - 1];
    if (level === 1) {
      if (previous !== undefined) {
        error('only one level 1 heading (the guide title) is allowed');
        return;
      }
      if (topic !== undefined) {
        error(`the guide title already has the topic "${id}": put the marker before a level 2 or 3 heading`);
      }
      if (when !== undefined) {
        error('a when marker applies to a level 2 or 3 heading, not to the guide title', when.line);
      }
    } else if (previous === undefined) {
      error('a guide starts with a level 1 heading (its title)');
      return;
    } else if (level > previous.level + 1) {
      error(`heading level skipped (level ${level} after level ${previous.level})`);
    }
    const section: HelpSection = {
      id: uniqueId(title),
      level: level as 1 | 2 | 3,
      title,
      blocks: [],
    };
    if (when !== undefined && level !== 1) {
      section.when = when.feature;
    }
    const sectionTopic = level === 1 ? id : topic?.topic;
    if (sectionTopic !== undefined) {
      section.topic = sectionTopic;
      if (topicLines.has(sectionTopic)) {
        error(`duplicate topic "${sectionTopic}"`, topic?.line ?? lineNo);
      } else {
        topicLines.set(sectionTopic, topic?.line ?? lineNo);
      }
    }
    sections.push(section);
    sectionLines.push(lineNo);
  }

  function figure(alt: string, path: string, caption: string | undefined): void {
    flush();
    if (alt.trim() === '') {
      error('an image needs an alternative text: ![description](…)');
    }
    const match = SCREENSHOT.exec(path);
    if (match === null) {
      error(`images are screenshots: ../screenshots/${lang}/<name>.png (got "${path}")`);
      return;
    }
    const [, imageLang, name] = match as unknown as [string, string, string];
    if (imageLang !== lang) {
      error(`screenshot of another language (${imageLang}) in a ${lang} guide`);
    }
    let size: { width: number; height: number } | undefined;
    if (!options.manifest.has(name)) {
      error(`screenshot "${name}" is not in docs/user/screenshots/manifest.json`);
    } else if (options.imageExists !== undefined && !options.imageExists(imageLang, name)) {
      error(`screenshot ${imageLang}/${name}.png is missing (run make screenshots)`);
    } else if (options.imageSize !== undefined) {
      size = options.imageSize(imageLang, name);
      if (size === undefined) {
        error(`screenshot ${imageLang}/${name}.png is not a valid PNG image`);
      }
    }
    const block: HelpBlock = { type: 'figure', src: `${imageLang}/${name}.png`, alt: alt.trim() };
    if (size !== undefined) {
      block.width = size.width;
      block.height = size.height;
    }
    if (caption !== undefined && caption.trim() !== '') {
      block.caption = caption.trim();
    }
    push(block, lineNo);
  }

  for (let i = 0; i < lines.length; i++) {
    lineNo = i + 1;
    const raw = lines[i] as string;
    const trimmed = raw.trim();
    const indent = raw.length - raw.trimStart().length;
    const isHeading = indent < 4 && HEADING.test(trimmed);
    const isMarker = TOPIC_MARKER.test(trimmed) || WHEN_MARKER.test(trimmed);

    const forbidden = forbiddenCharacter(raw);
    if (forbidden !== undefined) {
      error(`control or bidirectional formatting character ${forbidden} is not allowed`);
    }
    if (pendingTopic !== undefined && !isHeading && !isMarker) {
      error('a topic marker must be followed directly by a heading', pendingTopic.line);
      pendingTopic = undefined;
    }
    if (pendingWhen !== undefined && !isHeading && !isMarker) {
      error('a when marker must be followed directly by a heading', pendingWhen.line);
      pendingWhen = undefined;
    }
    if (trimmed === '') {
      if (list !== undefined) afterList = { ordered: list.ordered };
      flush();
      continue;
    }
    const listEnded = afterList;
    afterList = undefined;
    if (/\t/.test(raw.slice(0, indent))) {
      error('tabs are not allowed for indentation');
    }

    // Continuation of a list item (indented line) or a nested list.
    if (list !== undefined && indent > 0) {
      if (BULLET.test(trimmed) || ORDERED.test(trimmed)) {
        error('nested lists are not supported (one level only)');
      } else {
        list.items[list.items.length - 1]?.pieces.push({ text: trimmed, line: lineNo });
      }
      continue;
    }
    if (listEnded !== undefined) {
      if (indent > 0) {
        error('a list item cannot continue after a blank line (remove the blank line)');
        continue;
      }
      const isBullet = BULLET.test(trimmed) && !RULE.test(trimmed);
      if ((listEnded.ordered && ORDERED.test(trimmed)) || (!listEnded.ordered && isBullet)) {
        error('list items cannot be separated by a blank line (remove the blank line)');
      }
    }
    if (indent >= 4) {
      error('indented code blocks are not supported');
      continue;
    }
    if (/^(```|~~~)/.test(trimmed)) {
      error('code blocks are not supported (use `code` in a paragraph)');
      flush();
      const fence = trimmed.slice(0, 3);
      while (i + 1 < lines.length && !(lines[i + 1] as string).trim().startsWith(fence)) i++;
      i++;
      continue;
    }
    const marker = TOPIC_MARKER.exec(trimmed);
    if (marker !== null) {
      flush();
      const topic = marker[1] as string;
      if (!TOPIC_PATTERN.test(topic)) {
        error(`invalid topic "${topic}" (lower-case words separated by hyphens)`);
      } else if (RESERVED_TOPICS.includes(topic)) {
        error(`topic "${topic}" is reserved (printable page /help/${topic})`);
      } else if (pendingTopic !== undefined) {
        error('only one topic marker per heading');
      } else {
        pendingTopic = { topic, line: lineNo };
      }
      continue;
    }
    const whenMarker = WHEN_MARKER.exec(trimmed);
    if (whenMarker !== null) {
      flush();
      const feature = whenMarker[1] as string;
      if (GUIDE_APPS[id] === 'admin') {
        error('when markers are for the public guides only');
      } else if (!(HELP_FEATURES as readonly string[]).includes(feature)) {
        error(`unknown feature "${feature}" (${HELP_FEATURES.join(', ')})`);
      } else if (pendingWhen !== undefined) {
        error('only one when marker per heading');
      } else {
        pendingWhen = { feature: feature as HelpFeature, line: lineNo };
      }
      continue;
    }
    const rulesMarker = RULES_MARKER.exec(trimmed);
    if (rulesMarker !== null) {
      flush();
      const set = rulesMarker[1] as string;
      if (GUIDE_APPS[id] === 'admin') {
        error('rules markers are for the public guides only');
      } else if (!(RULES_SETS as readonly string[]).includes(set)) {
        error(`unknown rules set "${set}" (${RULES_SETS.join(', ')})`);
      } else if (sections.length === 0) {
        error('content before the guide title (level 1 heading)');
      } else {
        rules.push({ set: set as RulesSet, line: lineNo });
        push({ type: 'rules', set: set as RulesSet }, lineNo);
      }
      continue;
    }
    if (trimmed.startsWith('<!--') || /^<[A-Za-z/!?]/.test(trimmed)) {
      error('HTML is not supported (only the topic, when and rules markers <!-- topic: … -->)');
      flush();
      continue;
    }
    const head = HEADING.exec(trimmed);
    if (head !== null) {
      heading((head[1] as string).length, head[2] ?? '');
      continue;
    }
    if (RULE.test(trimmed)) {
      error('horizontal rules and underlined headings are not supported');
      flush();
      continue;
    }
    if (trimmed.startsWith('|') || (trimmed.includes('|') && TABLE_DELIMITER.test(trimmed))) {
      error('tables are not supported');
      flush();
      continue;
    }
    if (trimmed.startsWith('>')) {
      const content = trimmed.slice(1).replace(/^ /, '');
      if (content.startsWith('>')) {
        error('nested quotes are not supported');
        continue;
      }
      if (note !== undefined) {
        if (BULLET.test(content) || ORDERED.test(content) || HEADING.test(content)) {
          error('a note only holds text (no list or heading)');
        } else if (content.trim() === '') {
          error('a note is a single paragraph: remove the empty ">" line');
        } else {
          note.pieces.push({ text: content.trim(), line: lineNo });
        }
        continue;
      }
      flush();
      const label = /^\*\*([^*]+)\*\*\s*(.*)$/.exec(content);
      if (label === null) {
        error('a quote is a note starting with a bold label: > **Note** text');
        continue;
      }
      note = {
        label: (label[1] as string).replace(/\s*:\s*$/, '').trim(),
        pieces: [{ text: (label[2] as string).trim(), line: lineNo }],
        line: lineNo,
      };
      continue;
    }
    const bullet = BULLET.exec(trimmed);
    const ordered = bullet === null ? ORDERED.exec(trimmed) : null;
    if (bullet !== null || ordered !== null) {
      const isOrdered = ordered !== null;
      const text = ((bullet ?? ordered) as RegExpExecArray)[1] as string;
      if (list === undefined || list.ordered !== isOrdered) {
        flush();
        list = { ordered: isOrdered, items: [] };
      }
      list.items.push({ pieces: [{ text, line: lineNo }], line: lineNo });
      continue;
    }
    if (trimmed.startsWith('![')) {
      const image = IMAGE.exec(trimmed);
      if (image === null) {
        error('malformed image: ![alt text](../screenshots/<lang>/<name>.png "optional caption")');
        flush();
      } else {
        figure(image[1] as string, image[2] as string, image[3]);
      }
      continue;
    }
    // Text: lazy continuation of a list item or a note, or a paragraph line.
    const piece = { text: trimmed, line: lineNo };
    if (list !== undefined) {
      list.items[list.items.length - 1]?.pieces.push(piece);
    } else if (note !== undefined) {
      note.pieces.push(piece);
    } else if (para !== undefined) {
      para.pieces.push(piece);
    } else {
      para = { pieces: [piece], line: lineNo };
    }
  }
  lineNo = lines.length;
  flush();
  if (pendingTopic !== undefined) {
    error('a topic marker must be followed directly by a heading', pendingTopic.line);
  }
  if (pendingWhen !== undefined) {
    error('a when marker must be followed directly by a heading', pendingWhen.line);
  }
  if (sections.length === 0) {
    error('missing guide title (level 1 heading)', 1);
  }
  const first = sections[0];
  return {
    guide: { id, title: first?.title ?? id, sections },
    topicLines,
    rules,
    links,
    linkSections,
    sectionLines,
    errors,
  };
}

/** Source of one guide in one language. */
export interface GuideSource {
  lang: string;
  id: GuideId;
  /** File name used in the errors. */
  file: string;
  source: string;
}

/** Options of buildHelp. */
export interface BuildOptions {
  manifest: ReadonlySet<string>;
  imageExists?: ParseOptions['imageExists'];
  imageSize?: ParseOptions['imageSize'];
}

/** Result of buildHelp: one guide set per language and application, and every error. */
export interface BuildResult {
  sets: HelpGuideSet[];
  errors: HelpError[];
}

/**
 * Parses every guide and checks them together: each language has the four guides, topics are
 * unique in a language, internal links resolve (a section of the same guide, a topic of the same
 * application, never a topic of the super-admin guide from the delegated-admin guide), and every guide has the same topics in every language (the language switch keeps
 * the topic).
 */
export function buildHelp(sources: readonly GuideSource[], options: BuildOptions): BuildResult {
  const errors: HelpError[] = [];
  const parsed = new Map<string, { source: GuideSource; result: ParsedGuide }>();
  const key = (lang: string, id: GuideId): string => `${lang}/${id}`;
  for (const source of sources) {
    const result = parseGuide(source.source, {
      file: source.file,
      id: source.id,
      lang: source.lang,
      manifest: options.manifest,
      ...(options.imageExists === undefined ? {} : { imageExists: options.imageExists }),
      ...(options.imageSize === undefined ? {} : { imageSize: options.imageSize }),
    });
    errors.push(...result.errors);
    parsed.set(key(source.lang, source.id), { source, result });
  }
  const languages = [...new Set(sources.map((s) => s.lang))].sort();
  const sets: HelpGuideSet[] = [];

  for (const lang of languages) {
    const owner = new Map<string, { id: GuideId; file: string }>();
    for (const id of GUIDE_IDS) {
      const entry = parsed.get(key(lang, id));
      if (entry === undefined) {
        errors.push({ file: `docs/user/${lang}/${id}.md`, line: 1, message: 'missing guide' });
        continue;
      }
      for (const [topic, line] of entry.result.topicLines) {
        const other = owner.get(topic);
        if (other !== undefined) {
          errors.push({
            file: entry.source.file,
            line,
            message: `topic "${topic}" is already used in ${other.file}`,
          });
        } else {
          owner.set(topic, { id, file: entry.source.file });
        }
      }
    }
    for (const id of GUIDE_IDS) {
      const entry = parsed.get(key(lang, id));
      if (entry === undefined) continue;
      const sectionIds = new Set(entry.result.guide.sections.map((s) => s.id));
      for (const [linkIndex, link] of entry.result.links.entries()) {
        const from = whenChains(entry.result.guide.sections)[entry.result.linkSections[linkIndex] ?? 0] ?? [];
        const targetEntry =
          link.kind === 'anchor' ? entry : parsed.get(key(lang, owner.get(link.target)?.id ?? id));
        const targetSections = targetEntry?.result.guide.sections ?? [];
        const targetIndex = targetSections.findIndex((s) =>
          link.kind === 'anchor' ? s.id === link.target : s.topic === link.target,
        );
        const to = whenChains(targetSections)[targetIndex] ?? [];
        const hidden = to.find((feature) => !from.includes(feature));
        if (hidden !== undefined) {
          errors.push({
            file: entry.source.file,
            line: link.line,
            message: `link to a section shown only when ${hidden} is on: "${link.target}" (move the link or remove it)`,
          });
        }
        if (link.kind === 'anchor' && !sectionIds.has(link.target)) {
          errors.push({
            file: entry.source.file,
            line: link.line,
            message: `broken link #${link.target}: no section with this id in the guide`,
          });
        }
        if (link.kind === 'topic') {
          const target = owner.get(link.target);
          if (target === undefined) {
            errors.push({
              file: entry.source.file,
              line: link.line,
              message: `broken link topic:${link.target}: unknown topic`,
            });
          } else if (GUIDE_APPS[target.id] !== GUIDE_APPS[id]) {
            errors.push({
              file: entry.source.file,
              line: link.line,
              message: `link topic:${link.target} points to a guide of the other application (${target.id})`,
            });
          } else if (id === 'delegated-admin' && target.id === 'super-admin') {
            errors.push({
              file: entry.source.file,
              line: link.line,
              message: `link topic:${link.target} points to the super-admin guide, which a delegated admin cannot read`,
            });
          }
        }
      }
    }
    for (const app of ['public', 'admin'] as const) {
      const guides: HelpGuide[] = [];
      const topics: HelpGuideSet['topics'] = {};
      for (const id of GUIDE_IDS) {
        const entry = parsed.get(key(lang, id));
        if (GUIDE_APPS[id] !== app || entry === undefined) continue;
        guides.push(entry.result.guide);
        for (const section of entry.result.guide.sections) {
          if (section.topic !== undefined && owner.get(section.topic)?.id === id) {
            topics[section.topic] = { guide: id, section: section.id };
          }
        }
      }
      sets.push({ lang, app, guides, topics });
    }
  }

  // Same topics in every language, guide by guide.
  for (const id of GUIDE_IDS) {
    const all = languages.map((lang) => parsed.get(key(lang, id))).filter((entry) => entry !== undefined);
    const union = new Set(all.flatMap((entry) => [...entry.result.topicLines.keys()]));
    for (const entry of all) {
      for (const topic of union) {
        if (!entry.result.topicLines.has(topic)) {
          const elsewhere = all.find((other) => other.result.topicLines.has(topic));
          errors.push({
            file: entry.source.file,
            line: 1,
            message: `topic "${topic}" of ${elsewhere?.source.file ?? 'another language'} is missing in this language`,
          });
        }
      }
    }
    checkMarkerParity(all, errors);
  }
  return { sets, errors };
}

/**
 * Checks that the languages of a guide agree on the "when" marker of each level 2 or 3 section (by heading index)
 * and on the sequence of rules sets (the first language is the reference).
 */
function whenChains(sections: readonly HelpSection[]): HelpFeature[][] {
  const stack: { level: number; chain: HelpFeature[] }[] = [];
  return sections.map((section) => {
    while ((stack[stack.length - 1]?.level ?? 0) >= section.level) stack.pop();
    const chain = [
      ...(stack[stack.length - 1]?.chain ?? []),
      ...(section.when === undefined ? [] : [section.when]),
    ];
    stack.push({ level: section.level, chain });
    return chain;
  });
}

function checkMarkerParity(
  all: readonly { source: GuideSource; result: ParsedGuide }[],
  errors: HelpError[],
): void {
  const [reference, ...others] = all;
  if (reference === undefined) return;
  const referenceSections = reference.result.guide.sections;
  const sequence = (entry: { result: ParsedGuide }): string => entry.result.rules.map((r) => r.set).join(',');
  for (const entry of others) {
    for (const [index, section] of entry.result.guide.sections.entries()) {
      const other = referenceSections[index];
      if (section.level === 1 || other === undefined || other.when === section.when) continue;
      errors.push({
        file: entry.source.file,
        line: entry.result.sectionLines[index] ?? 1,
        message: `section "${section.title}" has a different when marker than in ${reference.source.file}`,
      });
    }
    if (sequence(entry) !== sequence(reference)) {
      const index = entry.result.rules.findIndex((r, i) => r.set !== reference.result.rules[i]?.set);
      const at = entry.result.rules[index === -1 ? entry.result.rules.length - 1 : index];
      errors.push({
        file: entry.source.file,
        line: at?.line ?? 1,
        message: `rules markers differ from ${reference.source.file} (same sets in the same order expected)`,
      });
    }
  }
}

/** File name of the generated module of a guide set ("fr-public.ts"). */
export function moduleFileName(set: Pick<HelpGuideSet, 'lang' | 'app'>): string {
  return `${set.lang}-${set.app}.ts`;
}

/** Reference to the n-th imported screenshot, written as the identifier image<n> by toSource. */
class ImageRef {
  readonly index: number;

  constructor(index: number) {
    this.index = index;
  }
}

/**
 * Writes a value as a TypeScript expression, indented like JSON.stringify(value, null, 2): strings
 * and numbers through JSON.stringify (the line and paragraph separators escaped as well), an
 * ImageRef as its identifier. No text of the guides is ever matched against a pattern, so no
 * content can turn into code.
 */
function toSource(value: unknown, depth: number): string {
  const pad = '  '.repeat(depth + 1);
  const end = '  '.repeat(depth);
  if (value instanceof ImageRef) {
    return `image${value.index}`;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    return `[\n${value.map((item) => pad + toSource(item, depth + 1)).join(',\n')}\n${end}]`;
  }
  if (typeof value === 'object' && value !== null) {
    const entries = Object.entries(value).filter(([, item]) => item !== undefined);
    if (entries.length === 0) return '{}';
    const body = entries.map(
      ([key, item]) => `${pad}${toSource(key, depth + 1)}: ${toSource(item, depth + 1)}`,
    );
    return `{\n${body.join(',\n')}\n${end}}`;
  }
  return (JSON.stringify(value) ?? 'null').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}

/**
 * Returns the TypeScript module of a guide set. Each screenshot becomes an import of its PNG
 * (importBase: path from the generated directory to docs/user/screenshots), which Vite copies,
 * fingerprinted, under /assets/; figure src is then the imported URL (the identifier image<n>,
 * written by toSource from the structure, never by a text substitution).
 */
export function generateModule(set: HelpGuideSet, importBase: string): string {
  const images = new Map<string, number>();
  const guides = set.guides.map((guide) => ({
    ...guide,
    sections: guide.sections.map((section) => ({
      ...section,
      blocks: section.blocks.map((block) => {
        if (block.type !== 'figure') return block;
        let index = images.get(block.src);
        if (index === undefined) {
          index = images.size;
          images.set(block.src, index);
        }
        return { ...block, src: new ImageRef(index) };
      }),
    })),
  }));
  const data = toSource({ lang: set.lang, app: set.app, guides, topics: set.topics }, 0);
  const imports = [...images].map(
    ([src, index]) => `import image${index} from ${JSON.stringify(`${importBase}/${src}`)};`,
  );
  return [
    `// Generated by scripts/build-help.mjs from docs/user/${set.lang}/ (${set.app} application): do not edit.`,
    "import type { HelpGuideSet } from '../types';",
    ...imports,
    '',
    `const guides: HelpGuideSet = ${data};`,
    '',
    'export default guides;',
    '',
  ].join('\n');
}
