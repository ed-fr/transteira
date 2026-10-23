<script lang="ts">
  // Deposit form (CLAUDE.md section 8.2): recipients (internal depositors only), message,
  // validity, optional password, delete after the first download, files. Client-side checks
  // mirror the server rules; on refusal, an error summary takes the focus and links to the
  // fields (RGAA 11.10).
  import { tick } from 'svelte';
  import {
    Alert,
    Button,
    Checkbox,
    FileDrop,
    FileList,
    RadioGroup,
    TextArea,
    TextField,
  } from '../../shared/components';
  import { formatBytes, t } from '../../shared/i18n/i18n.svelte';
  import type { DepositFlow } from './flow.svelte';
  import {
    fileIssues,
    invalidFields,
    MAX_FILES,
    MESSAGE_MAX_LENGTH,
    recipientIssues,
    type FormField,
    type Message,
  } from './form';
  import Countdown from './Countdown.svelte';
  import SessionBar from './SessionBar.svelte';

  interface Props {
    flow: DepositFlow;
    onnavigate?: ((path: string) => void) | undefined;
  }

  let { flow, onnavigate }: Props = $props();

  const ids: Record<FormField, string> = {
    recipients: 'tt-deposit-recipients',
    message: 'tt-deposit-message',
    expiryDays: 'tt-deposit-expiry',
    password: 'tt-deposit-password',
    files: 'tt-deposit-files',
  };

  let showPassword = $state(false);
  let remaining = $state(0);
  let summary: HTMLDivElement | undefined = $state();

  const say = (m: Message | undefined): string | undefined =>
    m === undefined ? undefined : t(m.key, m.params);

  const errors = $derived(flow.formErrors);
  const fields = $derived(invalidFields(errors));
  const recipientsError = $derived.by(() => {
    const parts: string[] = [];
    const general = say(errors['recipients']);
    if (general !== undefined) {
      parts.push(general);
    }
    for (const issue of recipientIssues(errors, flow.recipients)) {
      parts.push(
        t('deposit.form.recipients.addressError', {
          address: issue.address,
          message: say(issue.message) ?? '',
        }),
      );
    }
    return parts.length === 0 ? undefined : parts.join(' ');
  });
  const filesError = $derived.by(() => {
    const general = say(errors['files']);
    const names = fileIssues(errors, flow.form.files.length).size;
    if (general !== undefined) {
      return general;
    }
    return names > 0 ? t('deposit.form.files.invalidNames', { count: names }) : undefined;
  });
  const nameIssues = $derived(fileIssues(errors, flow.form.files.length));
  const overLimit = $derived(flow.totalBytes > flow.limits.maxTransferBytes);
  const expiryOptions = $derived(
    flow.limits.expiryDays.map((d) => ({ value: d, label: t('deposit.form.expiry.days', { count: d }) })),
  );

  function fieldLabel(field: FormField): string {
    switch (field) {
      case 'recipients':
        return t('deposit.form.recipients.label');
      case 'message':
        return t('deposit.form.message.label');
      case 'expiryDays':
        return t('deposit.form.expiry.legend');
      case 'password':
        return t('deposit.form.password.label');
      case 'files':
        return t('deposit.form.files.label');
    }
  }

  function focusField(event: MouseEvent, field: FormField): void {
    event.preventDefault();
    const target =
      field === 'expiryDays'
        ? document.querySelector<HTMLElement>(`input[name="${ids.expiryDays}"]`)
        : document.getElementById(ids[field]);
    target?.focus();
  }

  // Focus the error summary each time the form is refused.
  let refusals = 0;
  $effect(() => {
    const count = flow.formRefusals;
    if (count !== refusals) {
      refusals = count;
      void tick().then(() => summary?.focus());
    }
  });

  function submit(event: SubmitEvent): void {
    event.preventDefault();
    void flow.submitTransfer();
  }
</script>

<SessionBar {flow} {onnavigate} />

<h1 tabindex="-1">{t('deposit.form.title')}</h1>

{#if flow.notice}
  <Alert severity="info">{t(flow.notice.key, flow.notice.params)}</Alert>
{/if}

{#if flow.errorText}
  <Alert severity="error">{flow.errorText}</Alert>
{/if}

{#if fields.length > 0}
  <Alert severity="error" title={t('deposit.form.summary', { count: fields.length })} bind:element={summary}>
    <ul class="tt-mb-0">
      {#each fields as field (field)}
        <li><a href="#{ids[field]}" onclick={(e) => focusField(e, field)}>{fieldLabel(field)}</a></li>
      {/each}
    </ul>
  </Alert>
{/if}

<form class="tt-stack" novalidate onsubmit={submit}>
  {#if flow.isExternal}
    <Alert severity="info" live={false}>
      {t('deposit.form.recipients.external', { invitedBy: flow.invitedBy ?? '' })}
    </Alert>
  {:else}
    <TextArea
      id={ids.recipients}
      label={t('deposit.form.recipients.label')}
      hint={t('deposit.form.recipients.hint')}
      required
      rows={3}
      autocomplete="email"
      spellcheck={false}
      error={recipientsError}
      bind:value={flow.form.recipientsText}
    />
  {/if}

  <TextArea
    id={ids.message}
    label={t('deposit.form.message.label')}
    hint={t('deposit.form.message.hint')}
    maxlength={MESSAGE_MAX_LENGTH}
    rows={4}
    error={say(errors['message'])}
    bind:value={flow.form.message}
  />

  <RadioGroup
    legend={t('deposit.form.expiry.legend')}
    name={ids.expiryDays}
    options={expiryOptions}
    required
    inline
    error={say(errors['expiryDays'])}
    bind:value={flow.form.expiryDays}
  />

  <TextField
    id={ids.password}
    label={t('deposit.form.password.label')}
    type={showPassword ? 'text' : 'password'}
    autocomplete="new-password"
    hint={t('deposit.form.password.hint')}
    error={say(errors['password'])}
    bind:value={flow.form.password}
  >
    {#snippet addon()}
      <Button
        variant="secondary"
        small
        aria-pressed={showPassword}
        onclick={() => (showPassword = !showPassword)}
      >
        {showPassword ? t('deposit.form.password.hide') : t('deposit.form.password.show')}
      </Button>
    {/snippet}
  </TextField>

  <Checkbox
    label={t('deposit.form.deleteAfterFirstDownload.label')}
    hint={t('deposit.form.deleteAfterFirstDownload.hint')}
    bind:checked={flow.form.deleteAfterFirstDownload}
  />

  <FileDrop
    id={ids.files}
    label={t('deposit.form.files.label')}
    hint={t('deposit.form.files.hint', { max: formatBytes(flow.limits.maxTransferBytes), count: MAX_FILES })}
    required
    error={filesError}
    onfiles={(files) => flow.addFiles(files)}
  />

  <FileList
    files={flow.form.files}
    onremove={(index) => flow.removeFile(index)}
    disabled={flow.busy}
    showTotal
  >
    {#snippet details(_file, index)}
      {@const issue = nameIssues.get(index)}
      {#if issue}
        <p class="tt-text-danger tt-text-sm tt-mb-0">{say(issue)}</p>
      {/if}
    {/snippet}
  </FileList>

  {#if flow.form.files.length > 0}
    <p class="tt-text-sm" class:tt-text-danger={overLimit}>
      {t('deposit.form.files.total', {
        total: formatBytes(flow.totalBytes),
        max: formatBytes(flow.limits.maxTransferBytes),
      })}
    </p>
  {/if}

  <Countdown until={flow.retryAt} bind:remaining />
  <Button
    type="submit"
    loading={flow.busy}
    disabled={remaining > 0}
    loadingLabel={t('deposit.form.submitting')}
  >
    {t('deposit.form.submit')}
  </Button>
</form>
