// Client-side mirror of the server rules for file names and folder paths (api/openapi.yaml
// FilePath, internal/filename). The server stays the authority and refuses without correcting;
// mirroring the rules lets the form set aside a bad file with a clear message instead of failing
// the whole transfer.

/** Maximum length of a file or folder name, in bytes after NFC. */
export const SEGMENT_MAX_BYTES = 255;
/** Maximum length of a folder path, in bytes after NFC. */
export const PATH_MAX_BYTES = 1024;
/** Maximum number of folders in a path. */
export const PATH_MAX_SEGMENTS = 16;
/** Longest run of white space accepted in a name. */
export const MAX_SPACE_RUN = 2;

/** Why a name or path is refused (a stable code, translated as deposit.form.folders.reason.<code>). */
export type PathReason =
  | 'empty'
  | 'too-long'
  | 'control-character'
  | 'bidi-control'
  | 'invisible-character'
  | 'path-separator'
  | 'space-run'
  | 'dot-name'
  | 'leading-or-trailing-space-or-dot'
  | 'reserved-name'
  | 'empty-segment'
  | 'too-deep'
  | 'path-too-long';

/** Result of a check: the normalised value, or the reason of the refusal. */
export type PathCheck = { ok: true; value: string } | { ok: false; reason: PathReason };

const SEPARATORS = new Set([
  '/',
  '\\',
  ':',
  '\u2215',
  '\u2044',
  '\uff0f',
  '\u29f8',
  '\uff3c',
  '\uff1a',
  '\ua789',
  '\ufe55',
  '\u2236',
  '\ufe68',
  '\u2216',
]);
const CONTROL = /[\p{Cc}\u2028\u2029]/u;
const BIDI = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u;
const INVISIBLE = /[\p{Cf}\u034f\u115f\u1160\u3164\uffa0\ufe00-\ufe0f\u{e0100}-\u{e01ef}\u2800]/u;
const RESERVED = /^(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[0-9¹²³])$/;
const encoder = new TextEncoder();

/** Length in bytes of a string once encoded in UTF-8. */
export function byteLength(value: string): number {
  return encoder.encode(value).length;
}

/** Checks one file or folder name, returning it normalised to NFC (mirror of filename.Validate). */
export function checkSegment(name: string): PathCheck {
  if (name === '') {
    return { ok: false, reason: 'empty' };
  }
  const value = name.normalize('NFC');
  if (byteLength(value) > SEGMENT_MAX_BYTES) {
    return { ok: false, reason: 'too-long' };
  }
  let spaces = 0;
  for (const ch of value) {
    if (SEPARATORS.has(ch)) return { ok: false, reason: 'path-separator' };
    if (CONTROL.test(ch)) return { ok: false, reason: 'control-character' };
    if (BIDI.test(ch)) return { ok: false, reason: 'bidi-control' };
    if (INVISIBLE.test(ch)) return { ok: false, reason: 'invisible-character' };
    spaces = /\s/u.test(ch) ? spaces + 1 : 0;
    if (spaces > MAX_SPACE_RUN) return { ok: false, reason: 'space-run' };
  }
  if (/^\.+$/.test(value)) {
    return { ok: false, reason: 'dot-name' };
  }
  const first = [...value][0] ?? '';
  const last = [...value].pop() ?? '';
  if (/\s/u.test(first) || last === '.' || /\s/u.test(last)) {
    return { ok: false, reason: 'leading-or-trailing-space-or-dot' };
  }
  const stem = (value.split('.')[0] ?? '').replace(/ +$/, '').replace(/[a-z]/g, (c) => c.toUpperCase());
  if (RESERVED.test(stem)) {
    return { ok: false, reason: 'reserved-name' };
  }
  return { ok: true, value };
}

/**
 * Checks a folder path ('' is the root; segments separated by "/"), returning it normalised to
 * NFC (mirror of filename.ValidatePath).
 */
export function checkPath(path: string): PathCheck {
  if (path === '') {
    return { ok: true, value: '' };
  }
  const value = path.normalize('NFC');
  if (byteLength(value) > PATH_MAX_BYTES) {
    return { ok: false, reason: 'path-too-long' };
  }
  const segments = value.split('/');
  if (segments.length > PATH_MAX_SEGMENTS) {
    return { ok: false, reason: 'too-deep' };
  }
  for (const segment of segments) {
    if (segment === '') {
      return { ok: false, reason: 'empty-segment' };
    }
    const checked = checkSegment(segment);
    if (!checked.ok) {
      return checked;
    }
  }
  return { ok: true, value };
}
