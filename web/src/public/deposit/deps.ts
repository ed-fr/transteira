// Browser dependencies of the deposit flow: the shared API client, i18n, CSRF store, announcer,
// sessionStorage resume store, XMLHttpRequest tus transport, finalizeAndWait / waitForDecision
// and window.confirm.
import { api } from '../../shared/api/api';
import { csrf } from '../../shared/api/csrf.svelte';
import { announce } from '../../shared/components/announce.svelte';
import { i18n } from '../../shared/i18n/i18n.svelte';
import { createUploadEngine } from '../../shared/upload/engine';
import { finalizeAndWait, waitForDecision } from '../../shared/upload/finalize';
import { createResumeStore } from '../../shared/upload/resume-store';
import { createXhrTransport } from '../../shared/upload/transport-xhr';
import type { DepositFlowDeps } from './flow.svelte';

/** Dependencies of the deposit flow in the browser. */
export function browserDeps(): DepositFlowDeps {
  const transport = createXhrTransport({ csrfToken: () => csrf.current });
  return {
    api,
    tr: i18n,
    clearCsrf: () => csrf.clear(),
    resumeStore: createResumeStore(),
    createEngine: (specs, cancelTransfer) => createUploadEngine(specs, { transport, cancelTransfer }),
    finalize: (transferId, options) => finalizeAndWait(api, transferId, options),
    poll: (transferId, options) => waitForDecision(api, transferId, options),
    confirm: (message) => window.confirm(message),
    announce,
    language: () => i18n.locale.current,
  };
}
