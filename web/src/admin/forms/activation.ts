// Activation link of an admin account: AdminBaseURL + "/admin/activate#act_…". The token is in
// the fragment so that it never reaches a server log or a Referer header; the page reads it once,
// then removes it from the address bar with history.replaceState.

/**
 * Pattern of an activation token: "act_" and URL-safe characters, at most 128 characters in
 * total (ActivationRequest.activationToken). The server issues "act_" + 43 base62 characters.
 */
export const ACTIVATION_TOKEN = /^act_[A-Za-z0-9_-]{16,124}$/;

/** Returns the activation token of a location hash ("#act_…"), or null when absent or malformed. */
export function readActivationToken(hash: string): string | null {
  const token = hash.startsWith('#') ? hash.slice(1) : hash;
  return ACTIVATION_TOKEN.test(token) ? token : null;
}

/** Parts of a location used to rebuild the URL without its fragment. */
export interface LocationParts {
  pathname: string;
  search: string;
}

/** Returns the URL to give to history.replaceState: the same path and query, without the token. */
export function cleanActivationUrl(location: LocationParts): string {
  return location.pathname + location.search;
}
