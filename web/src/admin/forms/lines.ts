// Parsing of the one-value-per-line text areas of the administration (CIDR ranges, domains),
// with an error per line so that the form can point at the faulty line.

/** Result of the parsing of one value. */
export type ParseResult<E extends string> =
  { ok: true; value: string } | { ok: false; error: E; suggestion?: string };

/** Error of one line of a list, numbered from 1. */
export interface LineError<E extends string> {
  /** Line number in the text area, from 1. */
  line: number;
  /** The line as typed, trimmed. */
  raw: string;
  error: E;
  /** Corrected value to propose, when one can be inferred (e.g. a CIDR with host bits set). */
  suggestion?: string;
}

/** Result of the parsing of a text area. */
export interface LineList<E extends string> {
  /** Normalised values, in order, without duplicates; blank lines are ignored. */
  values: string[];
  /** One entry per invalid line. */
  errors: LineError<E>[];
  /** Line numbers whose normalised value repeats an earlier line (dropped from values). */
  duplicates: number[];
  /** True when values exceeds the maximum given to parseLineList. */
  tooMany: boolean;
}

/** Splits a text area into lines (LF, CRLF or CR). */
export function splitLines(text: string): string[] {
  return text.split(/\r\n|\r|\n/);
}

/**
 * Parses each non-blank line of text with parse. Values are kept in their normalised form and
 * deduplicated; max, when given, sets tooMany once exceeded.
 */
export function parseLineList<E extends string>(
  text: string,
  parse: (raw: string) => ParseResult<E>,
  max?: number,
): LineList<E> {
  const out: LineList<E> = { values: [], errors: [], duplicates: [], tooMany: false };
  const seen = new Set<string>();
  splitLines(text).forEach((line, i) => {
    const raw = line.trim();
    if (raw === '') {
      return;
    }
    const r = parse(raw);
    if (!r.ok) {
      const err: LineError<E> = { line: i + 1, raw, error: r.error };
      if (r.suggestion !== undefined) {
        err.suggestion = r.suggestion;
      }
      out.errors.push(err);
      return;
    }
    if (seen.has(r.value)) {
      out.duplicates.push(i + 1);
      return;
    }
    seen.add(r.value);
    out.values.push(r.value);
  });
  out.tooMany = max !== undefined && out.values.length > max;
  return out;
}

/** Joins values back into the text of a text area, one per line. */
export function joinLines(values: readonly string[]): string {
  return values.join('\n');
}
