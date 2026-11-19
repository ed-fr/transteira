<script lang="ts">
  // "Page not found" page of the administration (the server answers unknown paths with 404). Any
  // visitor can see it: signed out, PageLayout already renders it in its card, so the text only
  // goes in a card in the signed-in frame (inAdminFrame).
  import { t } from '../../shared/i18n/i18n.svelte';
  import ActionLink from '../components/ActionLink.svelte';
  import Card from '../components/Card.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import { adminSession } from '../api';
  import { inAdminFrame } from '../shell';
  import type { AdminScreenProps } from './types';

  let { nav }: AdminScreenProps = $props();
  const framed = $derived(inAdminFrame(adminSession));
</script>

<PageHeader title={t('common.notFound.title')} />
{#snippet content()}
  <p>{t('common.notFound.text')}</p>
  <p><ActionLink to="/" {nav} icon="home">{t('admin.backHome')}</ActionLink></p>
{/snippet}

{#if framed}
  <Card padding="lg">{@render content()}</Card>
{:else}
  {@render content()}
{/if}
