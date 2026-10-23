<script lang="ts">
  // Invitation landing page /i/:token (CLAUDE.md section 9): who invites, their message (text),
  // the expiry; "Continue" opens the deposit screen with the invitation context (code
  // verification of the invited address, files addressed to the inviter).
  import { onMount, tick } from 'svelte';
  import { api } from '../../shared/api/api';
  import { Button, Spinner } from '../../shared/components';
  import { formatDate, t } from '../../shared/i18n/i18n.svelte';
  import DepositScreen from '../deposit/DepositScreen.svelte';
  import ErrorPage from './ErrorPage.svelte';
  import NotFound from './NotFound.svelte';
  import { loadFailure, type PublicInvitation } from './outcomes';
  import type { ScreenProps } from './types';

  type State =
    | { kind: 'loading' }
    | { kind: 'ready'; invitation: PublicInvitation }
    | { kind: 'deposit'; invitation: PublicInvitation }
    | { kind: 'not-found' }
    | { kind: 'gone' }
    | { kind: 'error' };

  let { tenant, params, nav }: ScreenProps = $props();
  const token = $derived(params['token'] ?? '');
  let view = $state<State>({ kind: 'loading' });
  let retrying = $state(false);

  async function load(invitationToken: string): Promise<void> {
    try {
      const { data } = await api.get('/invitations/{invitationToken}', { path: { invitationToken } });
      view = { kind: 'ready', invitation: data };
    } catch (err) {
      view = { kind: loadFailure(err) };
    }
  }

  // Keyed on the path by App.svelte: the token never changes while mounted.
  onMount(() => {
    void load(token);
  });

  async function retry(): Promise<void> {
    retrying = true;
    await load(token);
    retrying = false;
  }

  async function proceed(invitation: PublicInvitation): Promise<void> {
    view = { kind: 'deposit', invitation };
    // The deposit screen replaces this page: move the focus to its heading.
    await tick();
    document.querySelector<HTMLElement>('h1[tabindex="-1"]')?.focus();
  }
</script>

{#if view.kind === 'loading'}
  <h1 tabindex="-1">{t('invitation.landing.title')}</h1>
  <Spinner showLabel />
{:else if view.kind === 'ready'}
  {@const invitation = view.invitation}
  <h1 tabindex="-1">{t('invitation.landing.title')}</h1>
  <p class="tt-break">{t('invitation.landing.text', { inviter: invitation.invitedBy })}</p>
  <dl class="tt-dl">
    <dt>{t('invitation.landing.invitedBy')}</dt>
    <dd>{invitation.invitedBy}</dd>
    <dt>{t('invitation.landing.email')}</dt>
    <dd>{invitation.email}</dd>
    <dt>{t('invitation.landing.expires')}</dt>
    <dd>{formatDate(invitation.expiresAt, { dateStyle: 'long' })}</dd>
  </dl>
  {#if invitation.message}
    <h2 class="tt-text-lg">{t('invitation.landing.message')}</h2>
    <p class="tt-break message">{invitation.message}</p>
  {/if}
  <p>{t('invitation.landing.next')}</p>
  <Button onclick={() => void proceed(invitation)}>{t('invitation.landing.continue')}</Button>
{:else if view.kind === 'deposit'}
  <DepositScreen
    {tenant}
    onnavigate={(path) => void nav.navigate(path)}
    addGuard={(guard) => nav.addGuard(guard)}
    invitation={{
      token,
      email: view.invitation.email,
      invitedBy: view.invitation.invitedBy,
      message: view.invitation.message,
    }}
  />
{:else if view.kind === 'not-found'}
  <NotFound
    {nav}
    title={t('invitation.invalid.title')}
    text={t('invitation.invalid.text')}
    homeLink={false}
  />
{:else if view.kind === 'gone'}
  <NotFound
    {nav}
    title={t('invitation.expired.title')}
    text={t('invitation.expired.text')}
    homeLink={false}
  />
{:else}
  <ErrorPage onretry={() => void retry()} {retrying} />
{/if}

<style>
  .message {
    white-space: pre-line;
  }
</style>
