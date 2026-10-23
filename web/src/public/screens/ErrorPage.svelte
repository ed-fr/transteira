<script lang="ts">
  // Generic error page with a retry button (failed loading, server or network error).
  import { Button } from '../../shared/components';
  import { t } from '../../shared/i18n/i18n.svelte';

  interface Props {
    /** Heading; defaults to "Something went wrong". */
    title?: string;
    /** Translated error message; defaults to the generic text. */
    message?: string;
    /** Retry handler; the button is hidden without it. */
    onretry?: () => void;
    /** Retry in progress. */
    retrying?: boolean;
  }

  let { title, message, onretry, retrying = false }: Props = $props();
</script>

<h1 tabindex="-1">{title ?? t('common.error.title')}</h1>
<p>{message ?? t('common.error.text')}</p>
{#if onretry}
  <Button onclick={onretry} loading={retrying}>{t('common.retry')}</Button>
{/if}
