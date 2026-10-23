<script lang="ts">
  // Live region: screen readers read each change of message. The region is always rendered
  // (a region inserted together with its text is often not announced); hidden visually by
  // default. For one-off announcements from anywhere, prefer announce() (Announcer.svelte).
  import type { Politeness } from './announce.svelte';

  interface Props {
    /** Text to announce; an empty string announces nothing. */
    message: string;
    /** polite (default) waits for the user to be idle; assertive interrupts. */
    politeness?: Politeness;
    /** Shows the message visually too. */
    visible?: boolean;
    class?: string;
  }

  let { message, politeness = 'polite', visible = false, class: className = '' }: Props = $props();
</script>

<div
  class={className}
  class:visually-hidden={!visible}
  role={politeness === 'assertive' ? 'alert' : 'status'}
  aria-live={politeness}
  aria-atomic="true"
>
  {message}
</div>
