<script lang="ts">
  // Neutral confirmation shown after an access link request: the same text whether the address
  // is known or not.
  import { onMount } from 'svelte';
  import { Button } from '../../shared/components';
  import { t } from '../../shared/i18n/i18n.svelte';

  interface Props {
    /** Goes back to the form (another address, or a new link). */
    onback: () => void;
  }

  let { onback }: Props = $props();
  let heading: HTMLElement | undefined = $state();

  onMount(() => heading?.focus());
</script>

<h1 tabindex="-1" bind:this={heading}>{t('myTransfers.request.sentTitle')}</h1>
<p>{t('myTransfers.request.sentText')}</p>
<p class="tt-text-muted tt-text-sm">{t('myTransfers.request.sentHint')}</p>
<div class="tt-cluster">
  <Button variant="secondary" onclick={onback}>{t('myTransfers.request.again')}</Button>
</div>
