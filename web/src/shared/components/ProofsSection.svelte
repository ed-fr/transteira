<script lang="ts">
  // "Proofs" section of a transfer detail (sender or admin): the proof of deposit, the proof of
  // delivery and, for per-recipient links, one proof of delivery per recipient who downloaded.
  // Each button fetches the PDF with the session cookie and saves it; a failure (404
  // proof-not-available, 429, ...) is shown in an alert below the buttons.
  import { ApiProblem } from '../api/client';
  import { problemMessage } from '../api/problem';
  import { depositProofAvailable, fetchProof, proofUrl, saveFile, type ProofKind } from '../api/proof';
  import { i18n, t } from '../i18n/i18n.svelte';
  import Alert from './Alert.svelte';
  import Button from './Button.svelte';
  import { announce } from './announce.svelte';

  interface Props {
    /** Transfer URL without the API prefix, segments encoded (see proofUrl). */
    base: string;
    /** Status of the transfer. */
    status: string;
    /** The transfer has been downloaded at least once. */
    delivered: boolean;
    /** Recipients who completed a download (per-recipient links). */
    recipients?: readonly string[];
    /** The session ended (401). */
    onexpired?: () => void;
    /** Heading id, for aria-labelledby of the section. */
    headingId: string;
  }

  let { base, status, delivered, recipients = [], onexpired, headingId }: Props = $props();

  let busy = $state<string | undefined>();
  let error = $state<string | undefined>();

  async function download(kind: ProofKind, recipient?: string): Promise<void> {
    if (busy !== undefined) {
      return;
    }
    busy = `${kind}:${recipient ?? ''}`;
    error = undefined;
    try {
      saveFile(
        await fetchProof(proofUrl(base, kind, recipient), kind, undefined, i18n.locale.current || 'en'),
      );
      announce(t('common.proofs.done'));
    } catch (err) {
      if (err instanceof ApiProblem && err.status === 401 && onexpired !== undefined) {
        onexpired();
        return;
      }
      error = problemMessage(i18n, err);
    } finally {
      busy = undefined;
    }
  }
</script>

<section aria-labelledby={headingId}>
  <h2 id={headingId} class="tt-text-lg">{t('common.proofs.title')}</h2>
  <p>{t('common.proofs.intro')}</p>
  <ul class="tt-list-plain proofs">
    <li>
      <Button
        variant="secondary"
        disabled={!depositProofAvailable(status)}
        loading={busy === 'deposit:'}
        onclick={() => void download('deposit')}>{t('common.proofs.deposit')}</Button
      >
      {#if !depositProofAvailable(status)}
        <span class="tt-text-muted tt-text-sm">{t('common.proofs.depositPending')}</span>
      {/if}
    </li>
    <li>
      <Button
        variant="secondary"
        disabled={!delivered}
        loading={busy === 'delivery:'}
        onclick={() => void download('delivery')}>{t('common.proofs.delivery')}</Button
      >
      {#if !delivered}
        <span class="tt-text-muted tt-text-sm">{t('common.proofs.deliveryPending')}</span>
      {/if}
    </li>
    {#each recipients as recipient (recipient)}
      <li>
        <Button
          variant="secondary"
          loading={busy === `delivery:${recipient}`}
          aria-label={t('common.proofs.deliveryFor', { recipient })}
          onclick={() => void download('delivery', recipient)}
          >{t('common.proofs.deliveryFor', { recipient })}</Button
        >
      </li>
    {/each}
  </ul>
  {#if error !== undefined}
    <Alert severity="error">{error}</Alert>
  {/if}
</section>

<style>
  .proofs {
    display: grid;
    gap: var(--tt-space-3);
    margin-bottom: var(--tt-space-4);
  }
</style>
