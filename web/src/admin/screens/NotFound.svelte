<script lang="ts">
  // "Page not found" page of the administration (the server answers unknown paths with 404).
  import { t } from '../../shared/i18n/i18n.svelte';
  import type { AdminScreenProps } from './types';

  let { nav }: AdminScreenProps = $props();
</script>

<h1 tabindex="-1">{t('common.notFound.title')}</h1>
<p>{t('common.notFound.text')}</p>
<p><a href={nav.href('/')} use:nav.link>{t('admin.backHome')}</a></p>
