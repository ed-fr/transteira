<script lang="ts">
  // End of the creation of a one-time secret: the full link (with its key) shown once with a
  // Copy button for a link delivery, or the recipient of the mail; the expiry and the button to
  // create another secret. The link is forgotten as soon as this screen is left (another tab, end
  // of the session, page left): it cannot be displayed again.
  import { onDestroy } from 'svelte';
  import { Alert, Button, CopyButton } from '../../shared/components';
  import { formatDate, t } from '../../shared/i18n/i18n.svelte';
  import SessionBar from '../deposit/SessionBar.svelte';
  import type { DepositFlow } from '../deposit/flow.svelte';
  import type { SecretCreateFlow } from './createFlow.svelte';

  interface Props {
    /** The deposit flow (session bar). */
    flow: DepositFlow;
    /** The secret flow, on its done step. */
    secret: SecretCreateFlow;
    onnavigate?: ((path: string) => void) | undefined;
  }

  let { flow, secret, onnavigate }: Props = $props();

  onDestroy(() => secret.forgetResult());

  const expires = $derived(
    secret.expiresAt === undefined
      ? undefined
      : formatDate(secret.expiresAt, { dateStyle: 'long', timeStyle: 'short' }),
  );
</script>

<SessionBar {flow} {onnavigate} />

<h1 tabindex="-1">{t('secretCreate.done.title')}</h1>

{#if secret.link}
  <section aria-labelledby="tt-secret-link-title" class="tt-stack">
    <h2 id="tt-secret-link-title">{t('secretCreate.done.linkTitle')}</h2>
    <p>{t('secretCreate.done.linkIntro')}</p>
    <Alert severity="warning" live={false}>
      <p class="tt-text-bold tt-mb-0">{t('secretCreate.done.shownOnce')}</p>
    </Alert>
    <p class="tt-mb-0">{t('secretCreate.done.linkLabel')}</p>
    <code class="tt-secret-link" data-testid="secret-done-link">{secret.link}</code>
    <div>
      <CopyButton text={secret.link} label={t('secretCreate.done.copy')} />
    </div>
    <p class="tt-text-sm tt-text-muted tt-mb-0">{t('secretCreate.done.clipboard')}</p>
  </section>
{:else if secret.sentTo}
  <Alert severity="success" live={false}>
    {t('secretCreate.done.sentTo', { recipient: secret.sentTo })}
  </Alert>
{/if}

<ul>
  {#if expires}
    <li>{t('secretCreate.done.expires', { date: expires })}</li>
  {/if}
  <li>{t('secretCreate.done.once')}</li>
  {#if secret.doneWithFile}
    <li>{t('secretCreate.done.fileNotScanned')}</li>
  {/if}
</ul>

<div class="tt-cluster">
  <Button onclick={() => secret.createAnother()}>{t('secretCreate.done.another')}</Button>
  <Button variant="secondary" loading={flow.busy} onclick={() => void flow.endSession()}>
    {t('deposit.session.end')}
  </Button>
</div>

<style>
  .tt-secret-link {
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
