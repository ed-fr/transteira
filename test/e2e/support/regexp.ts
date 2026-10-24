// Regular expressions built from test data (addresses, file names, URLs): every metacharacter is
// escaped, so that a "." or a "+" in an address matches itself only.

/** Escapes every RegExp metacharacter of text. */
export function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** A RegExp matching text literally, anywhere (^ and $ anchors are added by the options). */
export function re(text: string, opts: { start?: boolean; end?: boolean } = {}): RegExp {
  return new RegExp(`${opts.start ? '^' : ''}${escapeRegExp(text)}${opts.end ? '$' : ''}`);
}
