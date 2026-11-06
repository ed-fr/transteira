<script lang="ts">
  // Landing page of a permanent drop link /drop/:token (since 2.0, CLAUDE.md section 22): the
  // label of the link, how long the files are kept and the confidentiality level, never the
  // recipients. "Continue" opens the deposit screen with the drop link context: the depositor
  // gives their own address and confirms it with a code (asked at every use); the files go to the
  // recipients of the link, who are not shown, and the validity is imposed by the link. An unknown,
  // disabled, revoked or rotated link gets a clear "not valid" page.
  import { onMount, tick } from 'svelte';
  import { api } from '../../shared/api/api';
  import { Button, Spinner } from '../../shared/components';
  import { t } from '../../shared/i18n/i18n.svelte';
  import DepositScreen from '../deposit/DepositScreen.svelte';
  import ErrorPage from './ErrorPage.svelte';
  import NotFound from './NotFound.svelte';
  import { loadFailure, type PublicDropLink } from './outcomes';
  import type { ScreenProps } from './types';

  type State =
    | { kind: 'loading' }
    | { kind: 'ready'; link: PublicDropLink }
    | { kind: 'deposit'; link: PublicDropLink }
    | { kind: 'invalid' }
    | { kind: 'error' };

  let { tenant, params, nav }: ScreenProps = $props();
  const token = $derived(params['token'] ?? '');
  let view = $state<State>({ kind: 'loading' });
  let retrying = $state(false);

  async function load(dropToken: string): Promise<void> {
    try {
      const { data } = await api.get('/drop-links/{dropToken}', { path: { dropToken } });
      view = { kind: 'ready', link: data };
    } catch (err) {
      // 404 drop-link-invalid, and any other "not found" answer, is the same page.
      view = { kind: loadFailure(err) === 'error' ? 'error' : 'invalid' };
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

  async function proceed(link: PublicDropLink): Promise<void> {
    view = { kind: 'deposit', link };
    // The deposit screen replaces this page: move the focus to its heading.
    await tick();
    document.querySelector<HTMLElement>('h1[tabindex="-1"]')?.focus();
  }
</script>

{#if view.kind === 'loading'}
  <h1 tabindex="-1">{t('dropLink.landing.title')}</h1>
  <Spinner showLabel />
{:else if view.kind === 'ready'}
  {@const link = view.link}
  <h1 tabindex="-1">{t('dropLink.landing.title')}</h1>
  <p class="tt-break">{t('dropLink.landing.text', { label: link.label })}</p>
  <dl class="tt-dl">
    <dt>{t('dropLink.landing.label')}</dt>
    <dd class="tt-break">{link.label}</dd>
    <dt>{t('dropLink.landing.validity')}</dt>
    <dd>{t('dropLink.landing.validityValue', { count: link.validityDays })}</dd>
    {#if link.level}
      <dt>{t('dropLink.landing.level')}</dt>
      <dd class="tt-break">{link.level.label}</dd>
    {/if}
  </dl>
  <p>{t('dropLink.landing.next')}</p>
  <Button onclick={() => void proceed(link)}>{t('dropLink.landing.continue')}</Button>
{:else if view.kind === 'deposit'}
  <DepositScreen
    {tenant}
    onnavigate={(path) => void nav.navigate(path)}
    addGuard={(guard) => nav.addGuard(guard)}
    dropLink={{
      token,
      label: view.link.label,
      validityDays: view.link.validityDays,
      levelKey: view.link.level?.key,
    }}
  />
{:else if view.kind === 'invalid'}
  <NotFound {nav} title={t('dropLink.invalid.title')} text={t('dropLink.invalid.text')} homeLink={false} />
{:else}
  <ErrorPage onretry={() => void retry()} {retrying} />
{/if}
