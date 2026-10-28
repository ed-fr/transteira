<script lang="ts">
  // Webhooks of a tenant (CLAUDE.md section 12.4): the alerts of the entity (virus detected,
  // abuse, quotas) sent to Teams, Slack or a generic JSON receiver. The screen is WebhookManager
  // with the tenant scope, plus a notice telling whether the payloads carry the addresses
  // concerned (tenant setting webhookIncludeAddresses, changed on the General screen).
  // The tenant sub-navigation is rendered by App.svelte.
  import { untrack } from 'svelte';
  import { t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import { tenantPath } from '../../shell';
  import type { AdminScreenProps } from '../types';
  import WebhookManager from './WebhookManager.svelte';
  import { includesAddresses } from './webhooks';

  const { params, nav }: AdminScreenProps = $props();

  const tenantId = $derived(params['id'] ?? '');

  // Address setting of the tenant; undefined while unknown (the notice is then left out).
  let addresses = $state<boolean | undefined>(undefined);

  async function loadSetting(id: string): Promise<void> {
    addresses = undefined;
    try {
      const res = await adminApi.get('/admin/tenants/{tenantId}', { path: { tenantId: id } });
      addresses = includesAddresses(res.data);
    } catch {
      // The notice is optional: the list reports its own errors.
    }
  }

  $effect(() => {
    const id = tenantId;
    untrack(() => void loadSetting(id));
  });
</script>

{#snippet notice()}
  {#if addresses !== undefined}
    <p class="tt-text-sm">
      {addresses ? t('opsWebhooks.addresses.included') : t('opsWebhooks.addresses.excluded')}
      <a href={nav.href(tenantPath(tenantId, 'general'))} use:nav.link>{t('opsWebhooks.addresses.change')}</a>
    </p>
  {/if}
{/snippet}

<WebhookManager
  scope="tenant"
  {tenantId}
  title={t('adminOps.webhooks.title')}
  intro={t('adminOps.webhooks.intro')}
  {nav}
  {notice}
/>
