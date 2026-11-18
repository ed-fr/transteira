<script lang="ts">
  // Deposit form (CLAUDE.md sections 8.2 and 13.2): in the split public card, the files column on
  // the left (form/FilesColumn) and the details column on the right (form/DetailsColumn: sender,
  // recipients, message, level, duration, security options, submit), one column under the other on
  // narrow screens (files first). Messages and the error summary sit at the top of the card, above
  // both columns. Client-side checks mirror the server rules; on refusal, the error summary takes
  // the focus and links to the fields (RGAA 11.10): a field of the "Security options" block opens
  // it first, then gets the focus on the next tick.
  // The "Security options" block opens by itself when more options come into effect (at first,
  // chosen, or imposed by a change of level) and on a refusal when one of its fields is refused; it
  // never closes by itself, so a block the depositor closed stays closed on a refusal elsewhere.
  import { tick, untrack } from 'svelte';
  import { Alert } from '../../shared/components';
  import { t } from '../../shared/i18n/i18n.svelte';
  import type { DepositFlow } from './flow.svelte';
  import {
    fileIssues,
    hasSecurityError,
    invalidFields,
    isSecurityField,
    type FormField,
    type Message,
  } from './form';
  import DetailsColumn from './form/DetailsColumn.svelte';
  import FilesColumn from './form/FilesColumn.svelte';
  import { FIELD_IDS, focusTargetId, securityOpensOnCount } from './view';

  interface Props {
    flow: DepositFlow;
    onnavigate?: ((path: string) => void) | undefined;
  }

  let { flow, onnavigate }: Props = $props();

  let summary: HTMLDivElement | undefined = $state();
  let securityOpen = $state(false);

  const say = (m: Message | undefined): string | undefined =>
    m === undefined ? undefined : t(m.key, m.params);

  const errors = $derived(flow.formErrors);
  const fields = $derived(invalidFields(errors));
  const nameIssues = $derived(fileIssues(errors, flow.form.files.length));
  const filesError = $derived.by(() => {
    const general = say(errors['files']);
    if (general !== undefined) {
      return general;
    }
    return nameIssues.size > 0 ? t('deposit.form.files.invalidNames', { count: nameIssues.size }) : undefined;
  });
  const hasMessages = $derived(
    flow.notice !== undefined || flow.errorText !== undefined || fields.length > 0,
  );
  // More options in effect (chosen or imposed by the level) open the block.
  let securityCount = 0;
  $effect(() => {
    const count = flow.activeSecurityCount;
    if (securityOpensOnCount(securityCount, count)) {
      securityOpen = true;
    }
    securityCount = count;
  });

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
      case 'maxDownloads':
        return t('deposit.form.maxDownloads.label');
      case 'recipientVerification':
        return t('deposit.form.recipientVerification.label');
      case 'linkOnly':
        return t('deposit.form.linkOnly.label');
      case 'endToEnd':
        return t('deposit.e2e.label');
      case 'files':
        return t('deposit.form.files.label');
    }
  }

  async function focusField(event: MouseEvent, field: FormField): Promise<void> {
    event.preventDefault();
    if (isSecurityField(field) && !securityOpen) {
      securityOpen = true;
      // The panel is rendered (hidden removed) on the next tick.
      await tick();
    }
    const target =
      field === 'expiryDays'
        ? (document.querySelector<HTMLElement>(`input[name="${FIELD_IDS.expiryDays}"]:checked`) ??
          document.querySelector<HTMLElement>(`input[name="${FIELD_IDS.expiryDays}"]`))
        : document.getElementById(
            focusTargetId(field, { password: flow.passwordEnabled, maxDownloads: flow.maxDownloadsEnabled }),
          );
    target?.focus();
  }

  // Focus the error summary each time the form is refused, after opening the security block when
  // one of its fields is refused (only then: a refusal elsewhere leaves the block as it is).
  let refusals = 0;
  $effect(() => {
    const count = flow.formRefusals;
    if (count !== refusals) {
      refusals = count;
      if (hasSecurityError(untrack(() => flow.formErrors))) {
        securityOpen = true;
      }
      void tick().then(() => summary?.focus());
    }
  });

  function submit(event: SubmitEvent): void {
    event.preventDefault();
    void flow.submitTransfer();
  }
</script>

{#if hasMessages}
  <div class="tt-pcard__section tt-stack">
    {#if flow.notice}
      <Alert severity="info">{t(flow.notice.key, flow.notice.params)}</Alert>
    {/if}

    {#if flow.errorText}
      <Alert severity="error">{flow.errorText}</Alert>
    {/if}

    {#if fields.length > 0}
      <Alert
        severity="error"
        title={t('deposit.form.summary', { count: fields.length })}
        bind:element={summary}
      >
        <ul class="tt-mb-0 tt-deposit-summary">
          {#each fields as field (field)}
            <li>
              <a href="#{FIELD_IDS[field]}" onclick={(e) => void focusField(e, field)}>{fieldLabel(field)}</a>
            </li>
          {/each}
        </ul>
      </Alert>
    {/if}
  </div>
{/if}

<form class="tt-pcard__columns tt-deposit-form" novalidate onsubmit={submit}>
  <div class="tt-pcard__pane tt-pcard__pane--muted tt-stack">
    <FilesColumn {flow} error={filesError} {nameIssues} />
  </div>
  <div class="tt-pcard__pane tt-stack">
    <DetailsColumn {flow} {errors} {onnavigate} bind:securityOpen />
  </div>
</form>

<style>
  /*
   * The two panes of the deposit form: one column on phones and narrow windows (files first),
   * else 45 % files and 55 % details, so that the duration and the confidentiality level fit side
   * by side with their full labels (DetailsColumn stacks them again when they do not fit).
   */
  .tt-deposit-form {
    grid-template-columns: minmax(0, 1fr);
  }

  @media (min-width: 54rem) {
    .tt-deposit-form {
      grid-template-columns: minmax(0, 9fr) minmax(0, 11fr);
    }
  }

  /* Links of the error summary: 44 px targets (public pages). */
  .tt-deposit-summary a {
    display: inline-flex;
    align-items: center;
    min-height: var(--tt-control-height);
  }
</style>
