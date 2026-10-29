<script lang="ts">
  // "My transfers" page /me (CLAUDE.md section 8.7): a sender without an account manages their
  // transfers in progress. Flow: request form -> neutral confirmation -> mailed link
  // (/me#mta_...) -> session (cookie) -> list -> detail (extend, delete). The token travels in
  // the URL fragment: it is read once and removed from the address bar at once, then exchanged
  // for a session (kept in memory only until the exchange is settled, for a retry after a network
  // error). When a session is already active, the sender confirms before it is replaced (login
  // CSRF). A 401 at any time brings the sender back to the form.
  import { onMount } from 'svelte';
  import { api } from '../../shared/api/api';
  import { csrf } from '../../shared/api/csrf.svelte';
  import { Spinner } from '../../shared/components';
  import { t } from '../../shared/i18n/i18n.svelte';
  import {
    AccessTokenHolder,
    openAccessLink,
    parseAccessToken,
    type AccessLinkApi,
    type Phase,
  } from '../mytransfers/logic';
  import RequestForm from '../mytransfers/RequestForm.svelte';
  import SentNotice from '../mytransfers/SentNotice.svelte';
  import SwitchConfirm from '../mytransfers/SwitchConfirm.svelte';
  import TransferDetail from '../mytransfers/TransferDetail.svelte';
  import TransferList from '../mytransfers/TransferList.svelte';
  import ErrorPage from './ErrorPage.svelte';
  import type { ScreenProps } from './types';

  // The screen uses none of the route props.
  let {}: Partial<ScreenProps> = $props();

  let phase = $state<Phase>({ kind: 'loading' });
  let selected = $state<string | undefined>();
  let signingOut = $state(false);
  let failed = $state(false);
  // Access token of the link being opened, until its exchange is settled.
  const pending = new AccessTokenHolder();
  const linkApi: AccessLinkApi = {
    current: async () => (await api.get('/me/sessions/current')).data,
    start: async (token) => (await api.post('/me/sessions', { body: { token } })).data,
  };

  function toRequest(notice?: 'expired-session' | 'invalid-link'): void {
    csrf.clear();
    selected = undefined;
    phase = notice === undefined ? { kind: 'request' } : { kind: 'request', notice };
  }

  function expired(): void {
    toRequest('expired-session');
  }

  async function readSession(): Promise<void> {
    try {
      const { data } = await api.get('/me/sessions/current');
      phase = { kind: 'transfers', email: data.email, expiresAt: data.expiresAt };
    } catch {
      // No (valid) session: the request form. A network error shows the same form.
      toRequest();
    }
  }

  async function openLink(token: string, confirmed: boolean): Promise<void> {
    failed = false;
    phase = { kind: 'loading' };
    const out = await openAccessLink(linkApi, token, confirmed);
    switch (out.kind) {
      case 'signed-in':
        pending.clear();
        phase = { kind: 'transfers', email: out.email, expiresAt: out.expiresAt };
        break;
      case 'confirm-switch':
        phase = { kind: 'confirm-switch', email: out.email, expiresAt: out.expiresAt };
        break;
      case 'invalid-link':
        pending.clear();
        toRequest('invalid-link');
        break;
      default:
        // Network or server error: the token stays pending for the retry.
        failed = true;
    }
  }

  function stay(email: string, expiresAt: string): void {
    pending.clear();
    phase = { kind: 'transfers', email, expiresAt };
  }

  async function init(): Promise<void> {
    failed = false;
    phase = { kind: 'loading' };
    const fromFragment = parseAccessToken(window.location.hash) !== undefined;
    const token = pending.take(window.location.hash);
    if (fromFragment) {
      // Never keep the token in the address bar or in the history.
      window.history.replaceState(
        window.history.state,
        '',
        window.location.pathname + window.location.search,
      );
    }
    if (token !== undefined) {
      await openLink(token, false);
    } else {
      await readSession();
    }
  }

  function confirmSwitch(): void {
    const token = pending.take('');
    if (token === undefined) {
      toRequest('invalid-link');
      return;
    }
    void openLink(token, true);
  }

  onMount(() => {
    void init();
    // Opening the mailed link in a tab already showing /me changes the fragment only (no
    // reload): its token is exchanged as well.
    const onHashChange = (): void => {
      if (parseAccessToken(window.location.hash) !== undefined) {
        void init();
      }
    };
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  });

  async function signOut(): Promise<void> {
    signingOut = true;
    try {
      await api.delete('/me/sessions/current');
    } catch {
      // Already ended, or unreachable: the cookie is useless without a CSRF token anyway.
    } finally {
      signingOut = false;
    }
    toRequest();
  }
</script>

{#if failed}
  <ErrorPage onretry={() => void init()} />
{:else if phase.kind === 'loading'}
  <h1 tabindex="-1">{t('myTransfers.title')}</h1>
  <Spinner showLabel />
{:else if phase.kind === 'request'}
  <RequestForm notice={phase.notice} onsent={() => (phase = { kind: 'sent' })} />
{:else if phase.kind === 'sent'}
  <SentNotice onback={() => toRequest()} />
{:else if phase.kind === 'confirm-switch'}
  {@const current = phase}
  <SwitchConfirm
    email={current.email}
    onswitch={confirmSwitch}
    onstay={() => stay(current.email, current.expiresAt)}
  />
{:else if selected === undefined}
  <TransferList
    email={phase.email}
    onopen={(id) => (selected = id)}
    onexpired={expired}
    onsignout={() => void signOut()}
    {signingOut}
  />
{:else}
  <TransferDetail
    id={selected}
    onback={() => (selected = undefined)}
    ondeleted={() => (selected = undefined)}
    onexpired={expired}
  />
{/if}
