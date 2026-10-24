// Logic of the mail template screens (CLAUDE.md section 12.3), kept out of the components so
// that it is unit tested in Node: list grouped by template key with one column per language,
// server issues (part, line, column) mapped to the editor fields, insertion of a variable in the
// last focused field, extraction and neutralisation of the preview HTML (threat model T-163).
import type { ProblemFieldError } from '../../shared/api/client';
import type { components } from '../../shared/api/schema';
import { insertVariable, offsetOf, type TemplateParts } from '../forms/template';

export type EmailTemplateSummary = components['schemas']['EmailTemplateSummary'];
export type EmailTemplate = components['schemas']['EmailTemplate'];
export type EmailPreview = components['schemas']['EmailPreview'];

/** An editable part of a template. */
export type TemplatePart = keyof TemplateParts;

/** Parts in the order of the editor. */
export const TEMPLATE_PARTS: readonly TemplatePart[] = ['subject', 'bodyHtml', 'bodyText'];

/** Suffix of the translation keys of a part (adminTenants.templates.part.*). */
const PART_KEYS: Readonly<Record<TemplatePart, string>> = {
  subject: 'subject',
  bodyHtml: 'html',
  bodyText: 'text',
};

/** Translation key of the name of a part. */
export function partLabelKey(part: TemplatePart): string {
  return `adminTenants.templates.part.${PART_KEYS[part]}`;
}

/** Id of the input of a part, under the id prefix of the editor. */
export function partFieldId(prefix: string, part: TemplatePart): string {
  return `${prefix}-${part}`;
}

// ---- List ----------------------------------------------------------------------------------

/** One template key with its summary per language. */
export interface TemplateRow {
  key: string;
  cells: Record<string, EmailTemplateSummary | undefined>;
}

/** Templates grouped by key, with the languages as columns. */
export interface TemplateGrid {
  languages: string[];
  rows: TemplateRow[];
}

/**
 * Groups the summaries of listEmailTemplates by key (rows, in the order of the API) and by
 * language (columns: the languages of preferred first, in that order, then the others in the
 * order of the API). A language missing for a key leaves an undefined cell.
 */
export function groupTemplates(
  list: readonly EmailTemplateSummary[],
  preferred: readonly string[] = [],
): TemplateGrid {
  const seen = new Set(list.map((s) => s.language as string));
  const languages: string[] = [];
  for (const l of [...preferred, ...seen]) {
    if (seen.has(l) && !languages.includes(l)) {
      languages.push(l);
    }
  }
  const rows: TemplateRow[] = [];
  const byKey = new Map<string, TemplateRow>();
  for (const summary of list) {
    let row = byKey.get(summary.key);
    if (row === undefined) {
      row = { key: summary.key, cells: {} };
      byKey.set(summary.key, row);
      rows.push(row);
    }
    row.cells[summary.language] = summary;
  }
  return { languages, rows };
}

// ---- Editor --------------------------------------------------------------------------------

/** Reports whether two versions of a template differ. */
export function partsDiffer(a: TemplateParts, b: TemplateParts): boolean {
  return TEMPLATE_PARTS.some((p) => a[p] !== b[p]);
}

/** The editable parts of a template. */
export function partsOf(template: TemplateParts): TemplateParts {
  return { subject: template.subject, bodyHtml: template.bodyHtml, bodyText: template.bodyText };
}

/**
 * Inserts {{name}} in one part of the template, replacing the selection [start, end) of its
 * field. Returns the new parts (the others unchanged) and the cursor in the edited part.
 */
export function insertIntoPart(
  parts: TemplateParts,
  part: TemplatePart,
  name: string,
  start: number,
  end: number = start,
): { parts: TemplateParts; cursor: number } {
  const { text, cursor } = insertVariable(parts[part], name, start, end);
  return { parts: { ...parts, [part]: text }, cursor };
}

/** An issue reported by the server on a template (400 validation-failed). */
export interface TemplateIssue {
  /** Part concerned; undefined when the field is not a template part. */
  part: TemplatePart | undefined;
  /** 1-based line, when known. */
  line: number | undefined;
  /** 1-based column (code points), when known. */
  column: number | undefined;
  /** Explanation (English message of the server, else the translated field code). */
  message: string;
  /** True when message is the English message of the server (rendered with lang="en"). */
  fromServer: boolean;
}

/** Part named by a field of a problem ("/bodyHtml", "bodyHtml", "/bodyHtml/2"…). */
export function partOfField(field: string): TemplatePart | undefined {
  const name = field.replace(/^\//, '').split(/[/.]/)[0];
  return TEMPLATE_PARTS.find((p) => p === name);
}

function positive(n: number | undefined): number | undefined {
  return n !== undefined && Number.isInteger(n) && n >= 1 ? n : undefined;
}

/**
 * Maps the errors of a validation-failed problem to template issues, in the order of the API.
 * describe translates the field code when the server gave no message.
 */
export function templateIssues(
  errors: readonly ProblemFieldError[] | undefined,
  describe: (code: string) => string,
): TemplateIssue[] {
  return (errors ?? []).map((e) => {
    const fromServer = e.message !== undefined && e.message !== '';
    return {
      part: partOfField(e.field),
      line: positive(e.line),
      column: positive(e.column),
      message: fromServer ? (e.message as string) : describe(e.code),
      fromServer,
    };
  });
}

/** First issue message of each part (shown on the field, aria-invalid). */
export function issueByPart(issues: readonly TemplateIssue[]): Partial<Record<TemplatePart, string>> {
  const out: Partial<Record<TemplatePart, string>> = {};
  for (const issue of issues) {
    if (issue.part !== undefined && out[issue.part] === undefined) {
      out[issue.part] = issue.message;
    }
  }
  return out;
}

/**
 * Offset of an issue in the current text of its part (for setSelectionRange), or null when the
 * issue has no part or no line. The column defaults to the start of the line.
 */
export function issueOffset(parts: TemplateParts, issue: TemplateIssue): number | null {
  if (issue.part === undefined || issue.line === undefined) {
    return null;
  }
  return offsetOf(parts[issue.part], issue.line, issue.column ?? 1);
}

// ---- Preview -------------------------------------------------------------------------------

const BODY = /<body[^>]*>([\s\S]*)<\/body>/i;

/**
 * Content of the body of the rendered email (the server returns a whole document; inside the
 * page only the body content is shown). Returns the input when it has no body element.
 */
export function previewBody(html: string): string {
  const m = BODY.exec(html);
  return m === null ? html : (m[1] as string);
}

/** The part of an element used by neutralizePreview. */
export interface PreviewElement {
  /** Tag name (upper case in an HTML document); read for the headings only. */
  readonly tagName: string;
  removeAttribute(name: string): void;
  setAttribute(name: string, value: string): void;
}

/** The part of the preview container used by neutralizePreview. */
export interface PreviewRoot {
  querySelectorAll(selector: string): Iterable<PreviewElement>;
}

/** Deepest heading level of ARIA and HTML. */
const MAX_HEADING_LEVEL = 6;

/**
 * Level exposed for a heading of the email (h1 to h6) shown under a preview sub-heading of level
 * parentLevel: the headings of the email are nested one level below it, keeping their relative
 * order (h1 becomes parentLevel + 1, h2 parentLevel + 2…), capped at 6.
 */
export function previewHeadingLevel(tagName: string, parentLevel: number): number {
  const own = Number(tagName.slice(1));
  return Math.min(parentLevel + own, MAX_HEADING_LEVEL);
}

/**
 * Makes the rendered preview inert (threat model T-163): links lose their href and target (an
 * <a> without href is neither focusable nor followed) and get title; roles, ids and tabindex
 * are removed so that the email cannot add a landmark (its role="main"), clash with an id of
 * the page or take the focus. Then the headings of the email (the default templates start with
 * an <h1>) get role="heading" and an aria-level nested below the preview sub-heading of level
 * parentLevel (previewHeadingLevel), so that the page keeps a single level-1 heading and a
 * consistent outline; their look is unchanged.
 */
export function neutralizePreview(root: PreviewRoot, title: string, parentLevel: number): void {
  for (const link of root.querySelectorAll('a, area')) {
    link.removeAttribute('href');
    link.removeAttribute('target');
    link.setAttribute('title', title);
  }
  for (const el of root.querySelectorAll('[role], [id], [tabindex]')) {
    el.removeAttribute('role');
    el.removeAttribute('id');
    el.removeAttribute('tabindex');
  }
  for (const heading of root.querySelectorAll('h1, h2, h3, h4, h5, h6')) {
    heading.setAttribute('role', 'heading');
    heading.setAttribute('aria-level', String(previewHeadingLevel(heading.tagName, parentLevel)));
  }
}
