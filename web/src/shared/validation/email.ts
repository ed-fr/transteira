// Client-side check of an email address (OpenAPI Email: a bare address, at most 254 characters,
// no display name), shared by the public and admin applications.

/** Maximum length of an email address (Email). */
export const EMAIL_MAX_LENGTH = 254;

/**
 * Reports whether a value looks like a bare email address. Deliberately simple: the server has
 * the final word (validation-failed invalid-email), this only catches obvious typing mistakes.
 */
export function isEmail(value: string): boolean {
  return (
    value.length <= EMAIL_MAX_LENGTH && /^[^\s@<>(),;:"]+@[^\s@<>(),;:"]+\.[^\s@<>(),;:".]+$/.test(value)
  );
}
