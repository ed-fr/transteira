// JSON Merge Patch construction for the administration forms (TenantUpdate, AdminAccountUpdate…):
// only the allowed fields that changed are sent, and never null, which the API refuses.

/** Reports whether a and b are structurally equal (primitives, arrays and plain objects). */
export function deepEqual(a: unknown, b: unknown): boolean {
  if (Object.is(a, b)) {
    return true;
  }
  if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) {
    return false;
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) {
      return false;
    }
    return a.every((v, i) => deepEqual(v, b[i]));
  }
  const ka = Object.keys(a);
  const kb = Object.keys(b);
  if (ka.length !== kb.length) {
    return false;
  }
  const ra = a as Record<string, unknown>;
  const rb = b as Record<string, unknown>;
  return ka.every((k) => Object.prototype.hasOwnProperty.call(rb, k) && deepEqual(ra[k], rb[k]));
}

/**
 * Returns the merge patch turning original into edited, restricted to allowedKeys: a key is
 * present only when its edited value differs from the original one. Undefined and null edited
 * values are never sent (a merge patch cannot clear these fields), so an empty object means that
 * there is nothing to save.
 */
export function buildPatch<T extends object, K extends keyof T>(
  original: T,
  edited: T,
  allowedKeys: readonly K[],
): Partial<Pick<T, K>> {
  const patch: Partial<Pick<T, K>> = {};
  for (const key of allowedKeys) {
    const value = edited[key];
    if (value === undefined || value === null) {
      continue;
    }
    if (!deepEqual(original[key], value)) {
      patch[key] = value;
    }
  }
  return patch;
}

/** Reports whether a patch built by buildPatch has nothing to send. */
export function isEmptyPatch(patch: object): boolean {
  return Object.keys(patch).length === 0;
}
