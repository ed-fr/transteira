<script lang="ts">
  // Reply screen /d/:token/reply (CLAUDE.md section 10, version 1.1): the recipient of a transfer
  // sends files back to its sender. The reply session was opened by the download page
  // (POST /downloads/{token}/reply, cookie set by the server); this screen reads it and renders
  // the deposit screen in reply mode. Without a valid reply session (expired, direct visit, other
  // kind of session) the visitor goes back to the download page with a message.
  // The link back to the download page sits above the deposit screen, in a padded section of the
  // card when the deposit form splits it (the split card has no padding of its own).
  import { onMount } from 'svelte';
  import { api } from '../../shared/api/api';
  import { Alert, Spinner } from '../../shared/components';
  import { t } from '../../shared/i18n/i18n.svelte';
  import DepositScreen from '../deposit/DepositScreen.svelte';
  import type { ReplyContext } from '../deposit/flow.svelte';
  import { useCardFrame } from '../frame/card.svelte';
  import type { ScreenProps } from './types';

  type State = { kind: 'loading' } | { kind: 'ready'; reply: ReplyContext } | { kind: 'unavailable' };

  let { tenant, params, nav }: ScreenProps = $props();
  const token = $derived(params['token'] ?? '');
  let view = $state<State>({ kind: 'loading' });
  const frame = useCardFrame();
  const split = $derived(frame?.split === true);

  // Keyed on the path by App.svelte: the token never changes while mounted.
  onMount(() => {
    void load();
  });

  async function load(): Promise<void> {
    try {
      const { data } = await api.get('/deposit-sessions/current');
      if (data.kind === 'reply' && data.reply !== undefined) {
        view = {
          kind: 'ready',
          reply: { token, recipient: data.reply.recipient, transferExpiresAt: data.reply.transferExpiresAt },
        };
        return;
      }
    } catch {
      // No session, or the server is unreachable: the reply has to be started again.
    }
    view = { kind: 'unavailable' };
  }
</script>

{#if view.kind === 'loading'}
  <h1 tabindex="-1">{t('download.reply.page.title')}</h1>
  <Spinner showLabel />
{:else if view.kind === 'ready'}
  <div class:tt-pcard__section={split}>
    <p class="tt-text-sm">
      <a href={nav.href(`/d/${encodeURIComponent(token)}`)} use:nav.link>{t('download.reply.page.back')}</a>
    </p>
  </div>
  <DepositScreen
    {tenant}
    reply={view.reply}
    onreplyended={() => (view = { kind: 'unavailable' })}
    onnavigate={(path) => nav.navigate(path)}
    addGuard={(guard) => nav.addGuard(guard)}
  />
{:else}
  <h1 tabindex="-1">{t('download.reply.page.title')}</h1>
  <Alert severity="warning">{t('download.reply.page.unavailable')}</Alert>
  <p>
    <a href={nav.href(`/d/${encodeURIComponent(token)}`)} use:nav.link>{t('download.reply.page.back')}</a>
  </p>
{/if}
