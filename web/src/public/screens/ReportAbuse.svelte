<script lang="ts">
  // "Report an abuse" of the download page (CLAUDE.md section 10, version 1.1) and, since 2.3, of
  // the read page of an express secret (section 22.2, before and after reading): a secondary
  // button opening a dialog with the category (radio list) and an optional message (at most 1000
  // characters, counter). Works on the password and verification pages, without unlocking. The
  // report of a secret carries neither its key nor its text (abuseReport.ts).
  // Since 2.3 the trigger has two looks (variant): the default secondary button in its own
  // paragraph (secret pages), or an inline button styled as a text link in --tt-text, underlined,
  // at least 44 px high, for the bottom strip of the download page (on --tt-surface-muted, where
  // links never take the tenant colour). Both are real buttons named "Report an abuse".
  import { api } from '../../shared/api/api';
  import { Alert, Button, Dialog, RadioGroup, TextArea, announce } from '../../shared/components';
  import { t } from '../../shared/i18n/i18n.svelte';
  import {
    ABUSE_MESSAGE_MAX,
    categoryOptions,
    messageFits,
    reportBody,
    reportFailure,
    reportFailureKey,
    reportIntroKey,
    sendAbuseReport,
    type AbuseCategory,
    type ReportTarget,
  } from './abuseReport';

  interface Props {
    /** Link token of the download page, or of the secret link (target "secret"). */
    token: string;
    /** What is reported (default: the transfer of a download link). */
    target?: ReportTarget;
    /** Id of the button opening the dialog. */
    id?: string;
    /** Look of the trigger: a secondary button (default) or an inline text link. */
    variant?: 'button' | 'link';
  }

  let { token, target = 'transfer', id, variant = 'button' }: Props = $props();

  let open = $state(false);
  let category = $state<AbuseCategory | undefined>();
  let message = $state('');
  let sending = $state(false);
  let done = $state(false);
  let categoryError = $state<string | undefined>();
  let messageError = $state<string | undefined>();
  let failure = $state('');

  function show(): void {
    category = undefined;
    message = '';
    done = false;
    categoryError = undefined;
    messageError = undefined;
    failure = '';
    open = true;
  }

  async function send(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (sending) {
      return;
    }
    categoryError = undefined;
    messageError = undefined;
    failure = '';
    if (category === undefined) {
      categoryError = t('download.report.categoryRequired');
      return;
    }
    if (!messageFits(message)) {
      messageError = t('fieldErrors.too-long', { max: ABUSE_MESSAGE_MAX });
      return;
    }
    sending = true;
    try {
      await sendAbuseReport(api, target, token, reportBody(category, message));
      done = true;
      announce(t('download.report.sent'));
    } catch (err) {
      failure = t(reportFailureKey(reportFailure(err), target));
    } finally {
      sending = false;
    }
  }
</script>

{#if variant === 'link'}
  <span class="tt-report-inline">
    <Button {id} variant="link" class="tt-report__link" onclick={show}>{t('download.report.button')}</Button>
  </span>
{:else}
  <p class="tt-report">
    <Button {id} variant="secondary" small onclick={show}>{t('download.report.button')}</Button>
  </p>
{/if}

<Dialog bind:open title={t('download.report.title')} hideCloseButton={sending}>
  {#if done}
    <Alert severity="success">{t('download.report.sent')}</Alert>
  {:else}
    <form id="report-abuse-form" class="tt-stack" novalidate onsubmit={send}>
      <p>{t(reportIntroKey(target))}</p>
      {#if failure !== ''}
        <Alert severity="error">{failure}</Alert>
      {/if}
      <RadioGroup
        legend={t('download.report.category')}
        options={categoryOptions(t)}
        bind:value={category}
        required
        error={categoryError}
      />
      <TextArea
        label={t('download.report.message')}
        hint={t('download.report.messageHint')}
        bind:value={message}
        counterMax={ABUSE_MESSAGE_MAX}
        rows={4}
        error={messageError}
      />
    </form>
  {/if}
  {#snippet actions()}
    <Button
      variant="secondary"
      disabled={sending}
      onclick={() => {
        open = false;
      }}
    >
      {done ? t('download.report.close') : t('download.report.cancel')}
    </Button>
    {#if !done}
      <Button
        type="submit"
        form="report-abuse-form"
        loading={sending}
        loadingLabel={t('download.report.sending')}
      >
        {t('download.report.submit')}
      </Button>
    {/if}
  {/snippet}
</Dialog>

<style>
  .tt-report {
    margin-top: var(--tt-space-6);
  }

  /* Text link look on a muted surface: --tt-text, underlined (never the tenant link colour). */
  .tt-report-inline :global(.tt-report__link) {
    color: var(--tt-text);
  }
</style>
