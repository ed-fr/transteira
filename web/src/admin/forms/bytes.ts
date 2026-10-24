// Byte sizes of the administration forms (limit per transfer, storage quota), entered with a
// binary unit (base 1024) and sent to the API as an exact number of bytes (ByteSize).

/** Units offered by the size fields. */
export type ByteUnit = 'MiB' | 'GiB' | 'TiB';

/** Number of bytes of each unit. */
export const UNIT_BYTES: Readonly<Record<ByteUnit, number>> = {
  MiB: 2 ** 20,
  GiB: 2 ** 30,
  TiB: 2 ** 40,
};

/** Units in increasing order. */
export const BYTE_UNITS: readonly ByteUnit[] = ['MiB', 'GiB', 'TiB'];

/** Ceiling of the limit per transfer: 20 GiB (CLAUDE.md section 8.5, TenantUpdate). */
export const MAX_TRANSFER_BYTES = 20 * 2 ** 30;

/** Reasons for which a size is refused. */
export type ByteSizeError = 'invalid' | 'not-positive' | 'too-large';

/** Result of the parsing of a size field. */
export type ByteSizeResult = { ok: true; bytes: number } | { ok: false; error: ByteSizeError };

// Digits with at most three decimals, with a dot or a comma (French input).
const AMOUNT = /^[0-9]{1,15}([.,][0-9]{1,3})?$/;

/**
 * Parses an amount in unit into bytes (rounded to the nearest byte). The result must be a
 * positive safe integer, and at most max when given (e.g. MAX_TRANSFER_BYTES or the ceiling set
 * by the super admin).
 */
export function parseByteSize(amount: string, unit: ByteUnit, max?: number): ByteSizeResult {
  const s = amount.trim();
  if (!AMOUNT.test(s)) {
    return { ok: false, error: 'invalid' };
  }
  const bytes = Math.round(Number(s.replace(',', '.')) * UNIT_BYTES[unit]);
  if (!Number.isSafeInteger(bytes)) {
    return { ok: false, error: 'too-large' };
  }
  if (bytes < 1) {
    return { ok: false, error: 'not-positive' };
  }
  if (max !== undefined && bytes > max) {
    return { ok: false, error: 'too-large' };
  }
  return { ok: true, bytes };
}

/** Reports whether bytes is within the ceiling (inclusive). */
export function withinCeiling(bytes: number, ceiling: number = MAX_TRANSFER_BYTES): boolean {
  return bytes <= ceiling;
}

/**
 * Splits bytes into the value of a size field: the largest unit expressing it exactly, otherwise
 * the largest unit of which it is at least one, with up to three decimals.
 */
export function toFieldValue(bytes: number): { amount: string; unit: ByteUnit } {
  for (const unit of [...BYTE_UNITS].reverse()) {
    if (bytes >= UNIT_BYTES[unit] && bytes % UNIT_BYTES[unit] === 0) {
      return { amount: String(bytes / UNIT_BYTES[unit]), unit };
    }
  }
  const unit = [...BYTE_UNITS].reverse().find((u) => bytes >= UNIT_BYTES[u]) ?? 'MiB';
  return { amount: String(Math.round((bytes / UNIT_BYTES[unit]) * 1000) / 1000), unit };
}

const DISPLAY_UNITS: readonly [string, number][] = [
  ['TiB', 2 ** 40],
  ['GiB', 2 ** 30],
  ['MiB', 2 ** 20],
  ['KiB', 2 ** 10],
];

/** Formats bytes for display ("20 GiB", "1.5 MiB", "512 B") with the number format of locale. */
export function formatBytes(bytes: number, locale = 'en'): string {
  const nf = new Intl.NumberFormat(locale, { maximumFractionDigits: 2 });
  for (const [unit, size] of DISPLAY_UNITS) {
    if (bytes >= size) {
      return `${nf.format(bytes / size)} ${unit}`;
    }
  }
  return `${nf.format(bytes)} B`;
}
