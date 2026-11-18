<script lang="ts">
  // End of the creation of an express secret (CLAUDE.md section 22.2): the full link, composed by
  // the page with its key, shown once with a Copy button (when the clipboard refuses, the link is
  // selected for a manual copy), the expiry, the rules (the link is the secret, read once, pass it
  // through another channel than what it protects) and the button to create another secret, which
  // forgets the link. The link is forgotten too when this screen is left (ExpressSecret.svelte).
  import { Alert, Button, CopyButton } from '../../shared/components';
  import { formatDate, t } from '../../shared/i18n/i18n.svelte';
  import type { ExpressSecretFlow } from './expressFlow.svelte';

  interface Props {
    /** The express flow, on its done step. */
    flow: ExpressSecretFlow;
  }

  let { flow }: Props = $props();

  let linkElement: HTMLElement | undefined = $state();
  let copyFailed = $state(false);

  const expires = $derived(
    flow.expiresAt === undefined
      ? undefined
      : formatDate(flow.expiresAt, { dateStyle: 'long', timeStyle: 'short' }),
  );

  /** The clipboard refused the copy: select the link so that Ctrl+C copies it. */
  function selectLink(): void {
    copyFailed = true;
    const selection = window.getSelection();
    if (linkElement !== undefined && selection !== null) {
      selection.selectAllChildren(linkElement);
    }
  }
</script>

<h1 tabindex="-1">{t('secretExpress.done.title')}</h1>

{#if flow.link}
  <section aria-labelledby="tt-express-link-label" class="tt-stack">
    <Alert severity="warning" live={false}>
      <p class="tt-text-bold tt-mb-0">{t('secretExpress.done.shownOnce')}</p>
    </Alert>
    <p>{t('secretExpress.done.linkIsSecret')}</p>
    <p class="tt-mb-0" id="tt-express-link-label">{t('secretExpress.done.linkLabel')}</p>
    <!-- translate="no": a page translation service must never receive the link and its key. -->
    <code
      class="tt-express-link notranslate"
      id="tt-express-link"
      data-testid="express-done-link"
      translate="no"
      bind:this={linkElement}>{flow.link}</code
    >
    <div>
      <CopyButton
        text={flow.link}
        label={t('secretExpress.done.copy')}
        oncopy={(ok) => {
          if (ok) copyFailed = false;
          else selectLink();
        }}
      />
    </div>
    {#if copyFailed}
      <p class="tt-mb-0" id="tt-express-selected">{t('secretExpress.done.selected')}</p>
    {/if}
    <p class="tt-text-sm tt-text-muted tt-mb-0">{t('secretExpress.done.clipboard')}</p>
  </section>
{/if}

<ul>
  {#if expires}
    <li>{t('secretExpress.done.expires', { date: expires })}</li>
  {/if}
  <li>{t('secretExpress.done.once')}</li>
  <li>{t('secretExpress.done.otherChannel')}</li>
</ul>

<div class="tt-cluster">
  <Button id="tt-express-another" onclick={() => flow.createAnother()}
    >{t('secretExpress.done.another')}</Button
  >
</div>

<style>
  .tt-express-link {
    display: block;
    padding: var(--tt-space-3);
    border: var(--tt-border-width) solid var(--tt-border);
    border-radius: var(--tt-radius-sm);
    background: var(--tt-surface-muted);
    color: var(--tt-text);
    font-family: var(--tt-font-mono);
    word-break: break-all;
    user-select: all;
  }
</style>
