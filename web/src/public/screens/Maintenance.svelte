<script lang="ts">
  // Maintenance page (CLAUDE.md section 4): shown instead of the features refused during
  // maintenance. The super admin message is plain text, always rendered as text.
  import { t } from '../../shared/i18n/i18n.svelte';

  interface Props {
    /** Maintenance message of the super admin (PublicTenant.maintenanceMessage). */
    message?: string | undefined;
  }

  let { message }: Props = $props();
</script>

<h1 tabindex="-1">{t('common.maintenance.title')}</h1>
<p>{t('common.maintenance.text')}</p>
{#if message}
  <p class="tt-break maintenance-message">{message}</p>
{/if}

<style>
  .maintenance-message {
    white-space: pre-line;
  }
</style>
