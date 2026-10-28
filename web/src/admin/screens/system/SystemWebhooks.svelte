<script lang="ts">
  // Instance-wide webhooks (super admin, CLAUDE.md section 12.4): the system alerts (disk space,
  // antivirus outage, maintenance mode, master key rotation) sent to Teams, Slack or a generic
  // JSON receiver; never the events of an entity. The screen is WebhookManager with the system
  // scope. The system sub-navigation is rendered by App.svelte.
  import { t } from '../../../shared/i18n/i18n.svelte';
  import WebhookManager from '../ops/WebhookManager.svelte';
  import type { AdminScreenProps } from '../types';

  const { nav }: AdminScreenProps = $props();
</script>

<WebhookManager
  scope="system"
  title={t('adminSystem.webhooks.title')}
  intro={t('adminSystem.webhooks.intro')}
  {nav}
/>
