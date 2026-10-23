<script lang="ts">
  // Integrated help of the administration: placeholder until step 17.
  import { t } from '../../shared/i18n/i18n.svelte';
  import type { AdminScreenProps } from './types';

  let { params, nav }: AdminScreenProps = $props();
  const topic = $derived(params['topic']);
</script>

<h1 tabindex="-1">{t('common.help.title')}</h1>
<p>{t('common.help.comingSoon')}</p>
{#if topic}
  <p class="tt-text-muted tt-break">{t('common.help.topic', { topic })}</p>
{/if}
<p><a href={nav.href('/')} use:nav.link>{t('admin.backHome')}</a></p>
