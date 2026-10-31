<script lang="ts">
  // "Service being set up" page (PublicTenant.setupState === "setup"): shown instead of the
  // features the server refuses with 503 tenant-in-setup. Deliberately gives no detail about
  // what is missing in the configuration.
  import { t } from '../../shared/i18n/i18n.svelte';
</script>

<h1 tabindex="-1">{t('common.setup.title')}</h1>
<p>{t('common.setup.text')}</p>
