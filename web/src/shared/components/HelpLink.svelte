<script lang="ts">
  // Link to the integrated help for a topic (CLAUDE.md section 4.2): /help/<topic>, under the base
  // path of the application. With nav, the link is an in-app navigation (the help then offers
  // "back to the previous screen").
  import { t } from '../i18n/i18n.svelte';
  import type { LinkNode, Router } from '../router/router.svelte';
  import { helpHref } from './helpers';

  interface Props {
    /** Help topic slug (e.g. "deposit"); the help index when absent or invalid. */
    topic?: string;
    /** Path prefix of the application: "" (public, default) or "/admin". */
    base?: string;
    /** Router of the application: in-app navigation when given. */
    nav?: Pick<Router, 'link'> | undefined;
    /** Link text; defaults to "Help". */
    label?: string;
    class?: string;
  }

  let { topic, base = '', nav, label, class: className = '' }: Props = $props();

  function link(node: LinkNode): { destroy(): void } {
    return nav === undefined ? { destroy() {} } : nav.link(node);
  }
</script>

<a class="tt-help {className}" href={helpHref(topic, base)} use:link>{label ?? t('components.help.label')}</a>
