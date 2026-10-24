// Logic of ActivationLinkPanel, kept out of the component so that it is unit tested in Node.
// An activation link is shown once (createAdmin, resetAdminCredentials): until the super admin
// acknowledges it ("I have handed over the link"), leaving the page asks for a confirmation,
// through the router navigation guards and the beforeunload warning. The link itself is never
// part of a message, an announcement, a log, the URL or a storage (threat model T-162).

import type { NavigationGuard } from '../../shared/router/router.svelte';

/**
 * Navigation guard of a shown link: the navigation goes through once the link is acknowledged,
 * otherwise only when the user confirms leaving.
 */
export function activationLeaveGuard(
  isPending: () => boolean,
  confirm: (message: string) => boolean,
  message: string,
): NavigationGuard {
  return () => !isPending() || confirm(message);
}

/** Message of the leave confirmation (title, blank line, explanation); never contains the link. */
export function leaveMessage(t: (key: string) => string): string {
  return `${t('adminAccounts.activationLink.leaveConfirm.title')}\n\n${t('adminAccounts.activationLink.leaveConfirm.text')}`;
}

/** The part of a BeforeUnloadEvent used by the warning. */
export interface BeforeUnloadLike {
  preventDefault(): void;
  returnValue?: unknown;
}

/** beforeunload listener asking the browser to warn while the link is not acknowledged. */
export function activationBeforeUnload(isPending: () => boolean): (event: BeforeUnloadLike) => void {
  return (event) => {
    if (isPending()) {
      event.preventDefault();
      // Older browsers need returnValue set to show the dialog.
      event.returnValue = '';
    }
  };
}

/** Formatted expiry of a link, or undefined when the date is not valid. */
export function expiryText(
  expiresAt: string,
  formatDate: (date: Date) => string,
  t: (key: string, params: Record<string, string>) => string,
): string | undefined {
  const date = new Date(expiresAt);
  if (Number.isNaN(date.getTime())) {
    return undefined;
  }
  return t('adminAccounts.activationLink.expires', { date: formatDate(date) });
}
