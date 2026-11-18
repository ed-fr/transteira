<script lang="ts">
  // Details column of the deposit form (CLAUDE.md section 13.2, right pane): the "From" strip of the
  // verified sender, the recipients as chips (RecipientInput; an information message instead for a
  // drop link, a reply or an invited external depositor), the "Link only" switch right under them,
  // the message, the duration and the confidentiality level as segmented controls (side by side
  // when their legends and segments fit on one line, the hints wrapping inside their column; one
  // under the other otherwise; the order of the validated mockup), the "Security options" block,
  // and the full-width submit button showing the total volume ("Send · 4.2 GB": the separator is
  // hidden from screen readers, the volume is part of the accessible name). A change of level is
  // announced (duration changed, options in effect).
  import {
    Alert,
    announce,
    Button,
    Icon,
    RecipientInput,
    SegmentedControl,
    Switch,
    TextArea,
  } from '../../../shared/components';
  import { formatBytes, t } from '../../../shared/i18n/i18n.svelte';
  import Countdown from '../Countdown.svelte';
  import type { DepositFlow } from '../flow.svelte';
  import { MESSAGE_MAX_LENGTH, recipientIssueMap, type FormErrors, type Message } from '../form';
  import SessionBar from '../SessionBar.svelte';
  import { FIELD_IDS, levelChangeMessages } from '../view';
  import SecurityOptions from './SecurityOptions.svelte';

  interface Props {
    flow: DepositFlow;
    /** Field errors of the form. */
    errors: FormErrors;
    /** Open state of the "Security options" block (bindable). */
    securityOpen?: boolean;
    onnavigate?: ((path: string) => void) | undefined;
  }

  let { flow, errors, securityOpen = $bindable(false), onnavigate }: Props = $props();

  let remaining = $state(0);

  const say = (m: Message | undefined): string | undefined =>
    m === undefined ? undefined : t(m.key, m.params);

  const linkOnlyOn = $derived(flow.linkOnlyEffective);
  const committed = $derived(flow.committedRecipients);
  const recipientIssues = $derived(
    new Map(
      Array.from(recipientIssueMap(errors, committed.length), ([index, m]) => [index, t(m.key, m.params)]),
    ),
  );
  const levelOptions = $derived(
    flow.levels.map((l) => ({ value: l.key, label: l.label, description: l.description })),
  );
  const expiryOptions = $derived(
    flow.expiryOptions.map((d) => ({ value: d, label: t('deposit.form.expiry.days', { count: d }) })),
  );
  const showLevels = $derived(flow.levels.length > 1 && !flow.isDropLink);

  function chooseLevel(key: string): void {
    const before = { expiryDays: flow.form.expiryDays, securityCount: flow.activeSecurityCount };
    flow.setLevel(key);
    const after = { expiryDays: flow.form.expiryDays, securityCount: flow.activeSecurityCount };
    const messages = levelChangeMessages(before, after).map((m) => t(m.key, m.params));
    if (messages.length > 0) {
      announce(messages.join(' '));
    }
  }
</script>

<SessionBar {flow} {onnavigate} variant="strip" />

{#if flow.isDropLink}
  <Alert severity="info" live={false}>
    {t('deposit.form.recipients.dropLink', { label: flow.dropLinkLabel ?? '' })}
  </Alert>
{:else if flow.isReply}
  <Alert severity="info" live={false}>
    {t('deposit.form.recipients.reply', { recipient: flow.replyRecipient ?? '' })}
  </Alert>
{:else if flow.isExternal}
  <Alert severity="info" live={false}>
    {t('deposit.form.recipients.external', { invitedBy: flow.invitedBy ?? '' })}
  </Alert>
{:else}
  <div>
    <RecipientInput
      id={FIELD_IDS.recipients}
      label={t('deposit.form.recipients.label')}
      hint={linkOnlyOn ? t('deposit.form.recipients.optionalHint') : t('deposit.form.recipients.hint')}
      required={!linkOnlyOn}
      recipients={committed}
      issues={recipientIssues}
      error={say(errors['recipients'])}
      bind:draft={flow.form.recipientDraft}
      oncommit={() => flow.commitRecipientDraft()}
      onremove={(index) => flow.removeRecipient(index)}
    />
    {#if flow.linkOnlyOffered}
      <Switch
        id={FIELD_IDS.linkOnly}
        label={t('deposit.form.linkOnly.label')}
        checked={linkOnlyOn}
        locked={flow.linkOnlyBlockedByVerification
          ? t('deposit.form.linkOnly.blockedByVerification')
          : undefined}
        hint={t('deposit.form.linkOnly.hint')}
        error={say(errors['linkOnly'])}
        onchange={(on) => flow.setLinkOnly(on)}
      />
    {/if}
  </div>
{/if}

<TextArea
  id={FIELD_IDS.message}
  label={t('deposit.form.message.label')}
  hint={t('deposit.form.message.hint')}
  maxlength={MESSAGE_MAX_LENGTH}
  rows={3}
  error={say(errors['message'])}
  bind:value={flow.form.message}
/>

<div class="tt-deposit-choices">
  {#if flow.isDropLink}
    <p class="tt-mb-0">
      {t('deposit.form.expiry.forcedByLink', { count: flow.expiryOptions[0] ?? 0 })}
    </p>
  {:else}
    <SegmentedControl
      legend={t('deposit.form.expiry.legend')}
      name={FIELD_IDS.expiryDays}
      options={expiryOptions}
      required
      error={say(errors['expiryDays'])}
      bind:value={flow.form.expiryDays}
    />
  {/if}
  {#if showLevels}
    <SegmentedControl
      legend={t('deposit.form.level.legend')}
      hint={t('deposit.form.level.hint')}
      name="tt-deposit-level"
      options={levelOptions}
      required
      value={flow.level?.key}
      onchange={chooseLevel}
    />
  {/if}
</div>

<SecurityOptions {flow} {errors} bind:open={securityOpen} />

<div class="tt-deposit-submit">
  <Countdown until={flow.retryAt} bind:remaining />
  {#if flow.noUsableLevel}
    <Alert severity="error">{t('deposit.form.level.none')}</Alert>
  {:else}
    <Button
      type="submit"
      fullWidth
      class="tt-deposit-send"
      loading={flow.busy}
      disabled={remaining > 0}
      loadingLabel={t('deposit.form.submitting')}
    >
      <Icon name="send" />
      {t('deposit.form.submit')}{#if flow.form.files.length > 0}<span
          class="tt-deposit-send__dot"
          aria-hidden="true">·</span
        >{` ${formatBytes(flow.totalBytes)}`}{/if}
    </Button>
  {/if}
</div>

<style>
  /*
   * Duration and level side by side when both fit on one line, else one under the other. Each
   * group starts from the width of its legend and segments: the hint, the description of the
   * chosen level and the error do not widen it (inline-size containment), they wrap inside it.
   */
  .tt-deposit-choices {
    display: flex;
    flex-wrap: wrap;
    align-items: flex-start;
    gap: 0 var(--tt-space-6);
  }

  .tt-deposit-choices > :global(*) {
    flex: 1 1 auto;
  }

  .tt-deposit-choices :global(:is(.tt-seg__hint, .tt-seg__description, .tt-seg__error)) {
    contain: inline-size;
  }

  .tt-deposit-send__dot {
    margin-inline-start: 0.35em;
  }

  .tt-deposit-submit :global(.tt-deposit-send) {
    min-height: 3.25rem;
    font-size: var(--tt-font-size-lg);
  }
</style>
