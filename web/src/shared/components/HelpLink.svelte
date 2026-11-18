<script lang="ts">
  // Link to the integrated help for a topic (CLAUDE.md section 4.2): /help/<topic>, under the base
  // path of the application. With nav, the link is an in-app navigation (the help then offers
  // "back to the previous screen").
  //
  // Variants:
  //   'default'  text link "Help" (administration footer, public footer)
  //   'glass'    round glass link of the public header (section 13.2): a "?" icon, the label
  //              ("Help") as visually hidden text (accessible name) and as tooltip (title)
  import { t } from '../i18n/i18n.svelte';
  import type { LinkNode, Router } from '../router/router.svelte';
  import { helpHref } from './helpers';
  import Icon from './Icon.svelte';

  interface Props {
    /** Help topic slug (e.g. "deposit"); the help index when absent or invalid. */
    topic?: string | undefined;
    /** Path prefix of the application: "" (public, default) or "/admin". */
    base?: string;
    /** Router of the application: in-app navigation when given. */
    nav?: Pick<Router, 'link'> | undefined;
    /** Link text; defaults to "Help". */
    label?: string;
    /** Look of the link: default (text) or glass (public header). */
    variant?: 'default' | 'glass';
    class?: string;
  }

  let { topic, base = '', nav, label, variant = 'default', class: className = '' }: Props = $props();
  const text = $derived(label ?? t('components.help.label'));

  function link(node: LinkNode): { destroy(): void } {
    return nav === undefined ? { destroy() {} } : nav.link(node);
  }
</script>

{#if variant === 'glass'}
  <a
    class="tt-help tt-glass-btn tt-glass-btn--icon {className}"
    href={helpHref(topic, base)}
    title={text}
    use:link
  >
    <Icon name="help" />
    <span class="visually-hidden">{text}</span>
  </a>
{:else}
  <a class="tt-help {className}" href={helpHref(topic, base)} use:link>{text}</a>
{/if}
