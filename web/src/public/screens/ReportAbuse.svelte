<script lang="ts">
  // "Report an abuse" of the download page (CLAUDE.md section 10, version 1.1): a secondary
  // button opening a dialog with the category (radio list) and an optional message (at most 1000
  // characters, counter). Works on the password and verification pages, without unlocking.
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
    type AbuseCategory,
  } from './abuseReport';

  interface Props {
    /** Link token of the download page. */
    token: string;
  }

  let { token }: Props = $props();

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
      await api.post('/downloads/{linkToken}/abuse-reports', {
        path: { linkToken: token },
        body: reportBody(category, message),
      });
      done = true;
      announce(t('download.report.sent'));
    } catch (err) {
      failure = t(reportFailureKey(reportFailure(err)));
    } finally {
      sending = false;
    }
  }
</script>

<p class="tt-report">
  <Button variant="secondary" small onclick={show}>{t('download.report.button')}</Button>
</p>

<Dialog bind:open title={t('download.report.title')} hideCloseButton={sending}>
  {#if done}
    <Alert severity="success">{t('download.report.sent')}</Alert>
  {:else}
    <form id="report-abuse-form" class="tt-stack" novalidate onsubmit={send}>
      <p>{t('download.report.intro')}</p>
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
</style>
