// Mail template editor helpers: {{variable}} occurrences, client-side check of the missing and
// unknown variables, insertion at the cursor, and positions of the server issues (line, column).

/** Placeholder syntax of the mail templates (internal/mail). */
const PLACEHOLDER = /\{\{\s*([a-z0-9_]+)\s*\}\}/g;

/** One {{name}} occurrence in a text. */
export interface VariableOccurrence {
  name: string;
  /** Offset of the opening braces, in UTF-16 code units. */
  start: number;
  /** Offset just after the closing braces. */
  end: number;
}

/** Returns every {{name}} occurrence of text, in order. */
export function extractVariables(text: string): VariableOccurrence[] {
  return Array.from(text.matchAll(PLACEHOLDER), (m) => ({
    name: m[1] as string,
    start: m.index,
    end: m.index + m[0].length,
  }));
}

/** Parts of a template checked on the client. */
export interface TemplateParts {
  subject: string;
  bodyHtml: string;
  bodyText: string;
}

/** A required variable missing from a body. */
export interface MissingVariable {
  part: 'bodyHtml' | 'bodyText';
  name: string;
}

/** Result of checkTemplate. */
export interface TemplateCheck {
  /** Names used but not offered for this template, without duplicates. */
  unknown: string[];
  /** Required variables missing from a body (the server requires them in both bodies). */
  missing: MissingVariable[];
}

/**
 * Checks the variables of a template against those offered by the API (EmailTemplate.variables)
 * and the required ones. It is an early hint: the server checks the template fully (required
 * variables visible in the HTML, attribute contexts…) and stays authoritative.
 */
export function checkTemplate(
  parts: TemplateParts,
  variables: readonly string[],
  required: readonly string[] = [],
): TemplateCheck {
  const offered = new Set(variables);
  const unknown: string[] = [];
  for (const text of [parts.subject, parts.bodyHtml, parts.bodyText]) {
    for (const { name } of extractVariables(text)) {
      if (!offered.has(name) && !unknown.includes(name)) {
        unknown.push(name);
      }
    }
  }
  const missing: MissingVariable[] = [];
  for (const part of ['bodyHtml', 'bodyText'] as const) {
    const used = new Set(extractVariables(parts[part]).map((o) => o.name));
    for (const name of required) {
      if (!used.has(name)) {
        missing.push({ part, name });
      }
    }
  }
  return { unknown, missing };
}

/** Text and cursor after an insertion. */
export interface Insertion {
  text: string;
  /** Cursor offset, just after the inserted placeholder. */
  cursor: number;
}

function clamp(v: number, max: number): number {
  return Math.min(Math.max(0, Math.trunc(v)), max);
}

/**
 * Inserts "{{name}}" in text, replacing the selection [start, end) (a caret when equal); the
 * offsets are clamped to the text.
 */
export function insertVariable(text: string, name: string, start: number, end: number = start): Insertion {
  const a = clamp(Math.min(start, end), text.length);
  const b = clamp(Math.max(start, end), text.length);
  const token = `{{${name}}}`;
  return { text: text.slice(0, a) + token + text.slice(b), cursor: a + token.length };
}

/**
 * Converts a 1-based line and column (the column counted in Unicode code points, as the server
 * does) into a UTF-16 offset of text for setSelectionRange. Returns null for an unknown position
 * (line 0); a position beyond a line or the text is clamped to its end.
 */
export function offsetOf(text: string, line: number, column: number): number | null {
  if (!Number.isInteger(line) || line < 1) {
    return null;
  }
  let offset = 0;
  for (let l = 1; l < line; l++) {
    const nl = text.indexOf('\n', offset);
    if (nl < 0) {
      return text.length;
    }
    offset = nl + 1;
  }
  for (let c = 1; c < column && offset < text.length; c++) {
    const cp = text.codePointAt(offset) as number;
    if (cp === 0x0a) {
      break;
    }
    offset += cp > 0xffff ? 2 : 1;
  }
  return offset;
}
