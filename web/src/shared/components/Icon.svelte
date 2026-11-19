<script lang="ts">
  // Inline stroke icon (set in icons.ts): an <svg> of plain paths drawn in currentColor, so that it
  // follows the text colour of its context (and the system colours in forced colours mode).
  //
  // Props:
  //   name   icon of the set: alert, check, chevron, clock, copy, download, file, folder, globe,
  //          grid, help, home, info, list, lock, logs, menu, moon, plus, search, send, settings,
  //          shield, sun, upload, user, users, x
  //   size   'xs' (0.75rem), 'sm' (1rem), 'md' (1.25rem, default), 'lg' (1.5rem), 'xl' (2rem)
  //   label  accessible name: the icon is then role="img" with aria-label; without it (the
  //          default) the icon is decorative, aria-hidden="true", and the text next to it names
  //          the control
  //   class  extra classes (e.g. a rotation of the chevron)
  import { ICONS, type IconName } from './icons';

  interface Props {
    /** Icon of the set. */
    name: IconName;
    /** Size: xs, sm, md (default), lg or xl. */
    size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl';
    /** Accessible name; decorative (aria-hidden) when absent. */
    label?: string | undefined;
    class?: string;
  }

  let { name, size = 'md', label, class: className = '' }: Props = $props();
  const named = $derived(label !== undefined && label !== '');
</script>

<svg
  class="tt-icon tt-icon--{size} {className}"
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width="2"
  stroke-linecap="round"
  stroke-linejoin="round"
  focusable="false"
  role={named ? 'img' : undefined}
  aria-label={named ? label : undefined}
  aria-hidden={named ? undefined : 'true'}
>
  {#each ICONS[name] as d, index (index)}
    <path {d} />
  {/each}
</svg>

<style>
  .tt-icon {
    display: inline-block;
    flex: none;
    vertical-align: middle;
  }

  .tt-icon--xs {
    width: 0.75rem;
    height: 0.75rem;
  }

  .tt-icon--sm {
    width: 1rem;
    height: 1rem;
  }

  .tt-icon--md {
    width: 1.25rem;
    height: 1.25rem;
  }

  .tt-icon--lg {
    width: 1.5rem;
    height: 1.5rem;
  }

  .tt-icon--xl {
    width: 2rem;
    height: 2rem;
  }
</style>
