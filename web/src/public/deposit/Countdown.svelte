<script lang="ts">
  // Seconds left before a new attempt (rate limited): plain text updated every second (not a
  // live region, the error alert already announced the wait). remaining is bindable so that
  // the parent can disable its submit button until it reaches 0.
  import { t } from '../../shared/i18n/i18n.svelte';

  interface Props {
    /** Clock time (Date.now) of the next allowed attempt; nothing shown when undefined. */
    until: number | undefined;
    /** Translation key of the text, a plural group taking {count}. */
    messageKey?: string;
    /** Seconds left (bindable). */
    remaining?: number;
  }

  let { until, messageKey = 'common.retryAfter', remaining = $bindable(0) }: Props = $props();

  function left(): number {
    return until === undefined ? 0 : Math.max(0, Math.ceil((until - Date.now()) / 1000));
  }

  $effect(() => {
    remaining = left();
    if (remaining === 0) {
      return;
    }
    const timer = setInterval(() => {
      remaining = left();
      if (remaining === 0) {
        clearInterval(timer);
      }
    }, 1000);
    return () => clearInterval(timer);
  });
</script>

{#if remaining > 0}
  <p class="tt-text-muted tt-text-sm">{t(messageKey, { count: remaining })}</p>
{/if}
