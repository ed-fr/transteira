<script lang="ts">
  // Creation form of a one-time secret (CLAUDE.md section 22.1): text (with a counter), duration,
  // optional passphrase, optional file, delivery (link to copy, or e-mail to one recipient) and
  // read receipt. Client-side checks mirror the server rules (create.ts); on refusal, an error
  // summary takes the focus and links to the fields (RGAA 11.10). Also renders the working and
  // retry steps of the flow (createFlow.svelte.ts). The passphrase is kept out of password
  // managers (autocomplete off, opt-outs of 1Password, LastPass and Bitwarden): it is meant for one
  // secret only and must not be saved or offered for this site.
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
  import { helpHref } from '../../shared/components/helpers';
  import { formatBytes, t } from '../../shared/i18n/i18n.svelte';
  import Countdown from '../deposit/Countdown.svelte';
  import SessionBar from '../deposit/SessionBar.svelte';
  import type { DepositFlow } from '../deposit/flow.svelte';
  import { MAX_SECRET_RUNES, type Message, type SecretDelivery, type SecretField } from './create';
  import type { SecretCreateFlow } from './createFlow.svelte';

  interface Props {
    /** The deposit flow (session bar). */
    flow: DepositFlow;
    /** The secret flow. */
    secret: SecretCreateFlow;
    onnavigate?: ((path: string) => void) | undefined;
  }

  let { flow, secret, onnavigate }: Props = $props();

  const ids: Record<SecretField, string> = {
    text: 'tt-secret-text',
    expiresIn: 'tt-secret-duration',
    passphrase: 'tt-secret-passphrase',
    file: 'tt-secret-file',
    delivery: 'tt-secret-delivery',
    recipient: 'tt-secret-recipient',
  };

  let showPassphrase = $state(false);
  let remaining = $state(0);
  let summary: HTMLDivElement | undefined = $state();
  let problem: HTMLDivElement | undefined = $state();

  // A file size limit (params.max in bytes) is shown in binary multiples.
  const say = (m: Message | undefined): string | undefined =>
    m === undefined
      ? undefined
      : m.key === 'secretCreate.file.tooLarge'
        ? t(m.key, { max: formatBytes(Number(m.params?.['max'] ?? 0)) })
        : t(m.key, m.params);

  const errors = $derived(secret.errors);
  const fields = $derived(secret.invalidFields);
  const busy = $derived(secret.step !== 'form');
  const durationOptions = $derived(
    secret.features.durations.map((d) => ({ value: d, label: t(`secretCreate.duration.${d}`) })),
  );
  const deliveryOptions = $derived([
    {
      value: 'link' as SecretDelivery,
      label: t('secretCreate.delivery.link'),
      hint: t('secretCreate.delivery.linkHint'),
    },
    {
      value: 'email' as SecretDelivery,
      label: t('secretCreate.delivery.email'),
      hint: t('secretCreate.delivery.emailHint'),
    },
  ]);
  const files = $derived(secret.form.file === undefined ? [] : [secret.form.file]);
  const phaseLabel = $derived(t(`secretCreate.working.${secret.phase ?? 'sealing'}`));

  function fieldLabel(field: SecretField): string {
    switch (field) {
      case 'text':
        return t('secretCreate.text.label');
      case 'expiresIn':
        return t('secretCreate.duration.legend');
      case 'passphrase':
        return t('secretCreate.passphrase.label');
      case 'file':
        return t('secretCreate.file.label');
      case 'delivery':
        return t('secretCreate.delivery.legend');
      case 'recipient':
        return t('secretCreate.recipient.label');
    }
  }

  function focusField(event: MouseEvent, field: SecretField): void {
    event.preventDefault();
    const target =
      field === 'expiresIn' || field === 'delivery'
        ? document.querySelector<HTMLElement>(`input[name="${ids[field]}"]`)
        : document.getElementById(ids[field]);
    target?.focus();
  }

  // Focus the error summary (or the error message) each time the form is refused.
  let refusals = 0;
  $effect(() => {
    const count = secret.refusals;
    if (count !== refusals) {
      refusals = count;
      void tick().then(() => (summary ?? problem)?.focus());
    }
  });

  function submit(event: SubmitEvent): void {
    event.preventDefault();
    void secret.submit();
  }

  // Contextual help of the tab: in-app navigation when the router is there, a plain link otherwise.
  function openHelp(event: MouseEvent): void {
    if (
      onnavigate !== undefined &&
      !event.ctrlKey &&
      !event.metaKey &&
      !event.shiftKey &&
      event.button === 0
    ) {
      event.preventDefault();
      onnavigate(helpHref('secret-share'));
    }
  }
</script>

<SessionBar {flow} {onnavigate} />

<h1 tabindex="-1">{t('secretCreate.title')}</h1>
<p>{t('secretCreate.intro')}</p>
<p><a class="tt-help" href={helpHref('secret-share')} onclick={openHelp}>{t('secretCreate.help')}</a></p>

{#if secret.step === 'retry'}
  <Alert severity="error" title={t('secretCreate.retry.title')} bind:element={problem}>
    <p>{t('secretCreate.retry.text')}</p>
    {#if secret.errorText}
      <p class="tt-mb-0">{secret.errorText}</p>
    {/if}
  </Alert>
  <Countdown until={secret.retryAt} bind:remaining />
  <div class="tt-cluster">
    <Button disabled={remaining > 0} onclick={() => void secret.retry()}
      >{t('secretCreate.retry.again')}</Button
    >
    <Button variant="secondary" onclick={() => secret.abandon()}>{t('secretCreate.retry.abandon')}</Button>
  </div>
{:else if secret.errorText}
  <Alert severity="error" bind:element={problem}>{secret.errorText}</Alert>
{/if}

{#if fields.length > 0}
  <Alert severity="error" title={t('secretCreate.summary', { count: fields.length })} bind:element={summary}>
    <ul class="tt-mb-0">
      {#each fields as field (field)}
        <li><a href="#{ids[field]}" onclick={(e) => focusField(e, field)}>{fieldLabel(field)}</a></li>
      {/each}
    </ul>
  </Alert>
{/if}

{#if secret.step !== 'retry'}
  <form class="tt-stack" novalidate onsubmit={submit} aria-busy={busy}>
    <TextArea
      id={ids.text}
      label={t('secretCreate.text.label')}
      hint={secret.features.fileAllowed ? t('secretCreate.text.hintWithFile') : t('secretCreate.text.hint')}
      required={secret.form.file === undefined}
      rows={6}
      spellcheck={false}
      autocomplete="off"
      counterMax={MAX_SECRET_RUNES}
      countLength={(v) => [...v].length}
      readonly={busy}
      error={say(errors.text)}
      bind:value={secret.form.text}
    />

    <RadioGroup
      legend={t('secretCreate.duration.legend')}
      hint={t('secretCreate.duration.hint')}
      name={ids.expiresIn}
      options={durationOptions}
      required
      inline
      disabled={busy}
      error={say(errors.expiresIn)}
      bind:value={secret.form.expiresIn}
    />

    {#if secret.deliveryChoice}
      <RadioGroup
        legend={t('secretCreate.delivery.legend')}
        name={ids.delivery}
        options={deliveryOptions}
        required
        disabled={busy}
        error={say(errors.delivery)}
        bind:value={secret.form.delivery}
      />
    {:else if secret.emailOnly}
      <Alert severity="info" live={false}>
        {t('secretCreate.delivery.external', { recipient: secret.imposedRecipient ?? '' })}
      </Alert>
    {/if}

    {#if secret.delivery === 'email' && !secret.emailOnly}
      <TextField
        id={ids.recipient}
        label={t('secretCreate.recipient.label')}
        hint={t('secretCreate.recipient.hint')}
        type="email"
        autocomplete="email"
        spellcheck={false}
        required
        readonly={busy}
        error={say(errors.recipient)}
        bind:value={secret.form.recipient}
      />
    {/if}

    <TextField
      id={ids.passphrase}
      label={t('secretCreate.passphrase.label')}
      type={showPassphrase ? 'text' : 'password'}
      autocomplete="off"
      data-1p-ignore
      data-lpignore="true"
      data-bwignore
      required={secret.passphraseRequired}
      hint={secret.passphraseRequired
        ? t('secretCreate.passphrase.requiredHint')
        : t('secretCreate.passphrase.hint')}
      readonly={busy}
      error={say(errors.passphrase)}
      bind:value={secret.form.passphrase}
    >
      {#snippet addon()}
        <Button
          variant="secondary"
          small
          aria-pressed={showPassphrase}
          onclick={() => (showPassphrase = !showPassphrase)}
        >
          {showPassphrase ? t('secretCreate.passphrase.hide') : t('secretCreate.passphrase.show')}
        </Button>
      {/snippet}
    </TextField>
    {#if secret.delivery === 'email'}
      <Alert severity="warning" live={false}>{t('secretCreate.passphrase.otherChannel')}</Alert>
    {/if}

    {#if secret.features.fileAllowed}
      <FileDrop
        id={ids.file}
        label={t('secretCreate.file.label')}
        hint={t('secretCreate.file.hint', { max: formatBytes(secret.maxFileBytes) })}
        multiple={false}
        disabled={busy}
        error={say(errors.file)}
        onfiles={(picked) => secret.setFile(picked)}
      />
      <FileList
        {files}
        label={t('secretCreate.file.selected')}
        onremove={() => secret.removeFile()}
        disabled={busy}
      />
    {/if}

    <Checkbox
      id="tt-secret-read-receipt"
      label={t('secretCreate.readReceipt.label')}
      hint={t('secretCreate.readReceipt.hint')}
      disabled={busy}
      bind:checked={secret.form.readReceipt}
    />

    <Countdown until={secret.retryAt} bind:remaining />
    <Button type="submit" loading={busy} disabled={remaining > 0} loadingLabel={phaseLabel}>
      {t('secretCreate.submit')}
    </Button>
  </form>
{/if}
