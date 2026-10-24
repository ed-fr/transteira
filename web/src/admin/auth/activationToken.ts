// One-shot holder of the activation token (threat model T-162). The admin entry point (main.ts)
// calls captureActivationToken before the router is created and before the session bootstrap:
// on the activation page, the token is read from the fragment, kept in this module's memory and
// the fragment is removed from the address bar and the history entry right away. The token thus
// never stays in the URL while the bootstrap runs (nor when it fails), and never reaches
// router.current.hash. The activation screen takes it once (takeActivationToken clears it).
import { cleanActivationUrl, readActivationToken } from '../forms/activation';

/** Browser objects used by the capture (window.location and window.history). */
export interface ActivationCaptureEnv {
  location: { readonly pathname: string; readonly search: string; readonly hash: string };
  history: Pick<History, 'replaceState' | 'state'>;
}

let held: string | null = null;

/**
 * On the activation page (activatePath, for example "/admin/activate"), removes the fragment
 * from the URL and keeps the token it holds, when well formed. A malformed fragment is removed
 * too and nothing is kept. Other pages are left untouched.
 */
export function captureActivationToken(env: ActivationCaptureEnv, activatePath: string): void {
  const { location, history } = env;
  const pathname = location.pathname.replace(/\/+$/, '');
  if (pathname !== activatePath || location.hash === '') {
    return;
  }
  const token = readActivationToken(location.hash);
  history.replaceState(history.state, '', cleanActivationUrl(location));
  if (token !== null) {
    held = token;
  }
}

/** Returns the captured token and forgets it (null when none, or already taken). */
export function takeActivationToken(): string | null {
  const token = held;
  held = null;
  return token;
}
