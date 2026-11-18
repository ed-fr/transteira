<script lang="ts">
  // Express secret page /x (CLAUDE.md section 22.2, version 2.3): anyone who reaches the FQDN of
  // the tenant creates a one-time text secret, encrypted in this page, and gets its link once
  // (expressFlow.svelte.ts). Shown only when the tenant offers it
  // (PublicTenant.features.expressSecrets.enabled); otherwise a "not offered" page without form.
  // During maintenance the page shows the maintenance page (creation refused), and a tenant being
  // set up is handled by App.svelte. The link is forgotten when the page is hidden (pagehide, so a
  // page restored from the back-forward cache no longer shows it) or left; the server also sends
  // this page with Cache-Control: no-store.
  import { onDestroy, onMount, tick } from 'svelte';
  import { api } from '../../shared/api/api';
  import { announce } from '../../shared/components';
  import { formatDate, i18n, t } from '../../shared/i18n/i18n.svelte';
  import ExpressDone from '../secret/ExpressDone.svelte';
  import ExpressForm from '../secret/ExpressForm.svelte';
  import { ExpressSecretFlow } from '../secret/expressFlow.svelte';
  import { webCryptoAvailable } from './e2e';
  import Maintenance from './Maintenance.svelte';
  import NotFound from './NotFound.svelte';
  import type { ScreenProps } from './types';

  let { tenant, nav }: ScreenProps = $props();

  const flow = new ExpressSecretFlow(
    {
      get tenant() {
        return tenant;
      },
    },
    {
      api,
      tr: i18n,
      announce: (message, politeness) => announce(message, politeness),
      origin: () => window.location.origin,
      formatTime: (ms) => formatDate(ms, { timeStyle: 'short' }),
    },
  );
  const cryptoAvailable = webCryptoAvailable();
  let container: HTMLElement | undefined = $state();

  const forget = (): void => flow.forgetResult();
  onMount(() => {
    window.addEventListener('pagehide', forget);
    return () => window.removeEventListener('pagehide', forget);
  });
  onDestroy(forget);

  // Focus the heading when the secret is created and when another one is started (not on the
  // first render: the router handles it).
  let previous = flow.step;
  $effect(() => {
    const step = flow.step;
    if (step !== previous) {
      const moved = step === 'done' || previous === 'done';
      previous = step;
      if (moved) {
        void tick().then(() => container?.querySelector<HTMLElement>('h1')?.focus());
      }
    }
  });
</script>

<div bind:this={container}>
  {#if tenant.maintenance}
    <Maintenance message={tenant.maintenanceMessage} language={tenant.maintenanceMessageLanguage} />
  {:else if !flow.offered}
    <NotFound
      {nav}
      title={t('secretExpress.title')}
      text={t('secretExpress.notOffered', { entity: tenant.name })}
    />
  {:else if !cryptoAvailable}
    <NotFound
      {nav}
      title={t('secretExpress.unsupported.title')}
      text={t('secretExpress.unsupported.text')}
      homeLink={false}
    />
  {:else if flow.step === 'done'}
    <ExpressDone {flow} />
  {:else}
    <ExpressForm {flow} />
  {/if}
</div>
