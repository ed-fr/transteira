// Logic of SecretOnceModal, kept out of the component so that it is unit tested in Node. A
// secret shown once (e.g. a new API token) can only be dismissed once the admin copied it
// successfully (a failed copy does not count) or ticked "I have stored this secret"; until then, closing the dialog (Escape) is refused and
// leaving the page asks for a confirmation (router guard and beforeunload warning, as for the
// activation link, threat model T-162). The secret is never part of a message or announcement.

/**
 * Copied state after a copy attempt: true once a copy succeeded (it stays true), unchanged
 * after a failed copy (a failure never makes the dialog dismissable).
 */
export function copiedAfter(copied: boolean, ok: boolean): boolean {
  return copied || ok;
}

/** Reports whether the dialog may be closed: once acknowledged or copied successfully. */
export function canDismissSecret(acknowledged: boolean, copied: boolean): boolean {
  return acknowledged || copied;
}

/** Reports whether the secret is still pending (shown, not empty, not yet dismissable). */
export function secretPending(secret: string, acknowledged: boolean, copied: boolean): boolean {
  return secret !== '' && !canDismissSecret(acknowledged, copied);
}

/** The part of a cancel Event used by the dialog guard. */
export interface CancelEventLike {
  preventDefault(): void;
}

/**
 * Listener of the native cancel event of the dialog (Escape): refused while the secret is
 * pending, so that the dialog stays open.
 */
export function secretCancelGuard(isPending: () => boolean): (event: CancelEventLike) => void {
  return (event) => {
    if (isPending()) {
      event.preventDefault();
    }
  };
}

/** Message of the leave confirmation (title, blank line, explanation); never contains the secret. */
export function secretLeaveMessage(t: (key: string) => string): string {
  return `${t('adminComponents.secretOnce.leaveConfirm.title')}\n\n${t('adminComponents.secretOnce.leaveConfirm.text')}`;
}
