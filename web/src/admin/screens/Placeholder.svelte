<script lang="ts">
  // Administration home: placeholder until the admin screens (step 16).
  import { t } from '../../shared/i18n/i18n.svelte';
  import type { AdminScreenProps } from './types';

  // Route props (no API call, no parameter used yet).
  const _props: AdminScreenProps = $props();
</script>

<h1 tabindex="-1">{t('admin.placeholder.title')}</h1>
<p>{t('admin.placeholder.text')}</p>
