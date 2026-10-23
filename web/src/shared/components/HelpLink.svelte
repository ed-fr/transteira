<script lang="ts">
  // Link to the integrated help for a topic (CLAUDE.md section 4.2). Stub until step 17: it
  // points to /help/<topic>, a route reserved by both applications.
  import { t } from '../i18n/i18n.svelte';
  import { helpHref } from './helpers';

  interface Props {
    /** Help topic slug (e.g. "deposit"); the help index when absent or invalid. */
    topic?: string;
    /** Path prefix of the application: "" (public, default) or "/admin". */
    base?: string;
    /** Link text; defaults to "Help". */
    label?: string;
    class?: string;
  }

  let { topic, base = '', label, class: className = '' }: Props = $props();
</script>

<a class="tt-help {className}" href={helpHref(topic, base)}>{label ?? t('components.help.label')}</a>
