<script lang="ts">
  // "Security options" block of the deposit form (CLAUDE.md section 13.2): a disclosure (a button
  // with aria-expanded, never <details>) whose name carries the number of options in effect
  // ("Security options 2 active"), holding one switch per option:
  //   - "Protect with a password", revealing the password field (id tt-deposit-password, label
  //     "Password", with Show / Hide); turning it off clears the password;
  //   - "Recipients must verify their address by code" (when the tenant offers it);
  //   - "Delete the transfer after the first download";
  //   - "Limit the number of downloads", revealing the number field (id tt-deposit-max-downloads);
  //     turning it off clears the field;
  //   - "Encrypt end to end in my browser" (id tt-deposit-e2e, when the policy allows it).
  // An option imposed by the confidentiality level or the organisation is on and locked, with the
  // reason next to a lock icon. The parent opens the block (bind:open) when more options come into
  // effect, on a refusal when one of its fields is refused, and before focusing a field from the
  // error summary.
  import { Button, Disclosure, Switch, TextField } from '../../../shared/components';
  import { t } from '../../../shared/i18n/i18n.svelte';
  import type { DepositFlow } from '../flow.svelte';
  import { maxDownloadsCap, type FormErrors, type Message } from '../form';
  import { FIELD_IDS, SWITCH_IDS } from '../view';

  interface Props {
    flow: DepositFlow;
    /** Field errors of the form. */
    errors: FormErrors;
    /** Open state of the block (bindable). */
    open?: boolean;
  }

  let { flow, errors, open = $bindable(false) }: Props = $props();

  let showPassword = $state(false);

  const say = (m: Message | undefined): string | undefined =>
    m === undefined ? undefined : t(m.key, m.params);

  const count = $derived(flow.activeSecurityCount);
  const linkOnlyOn = $derived(flow.linkOnlyEffective);
  const verificationForced = $derived(flow.rules?.requireRecipientVerification === true);
  const deleteForced = $derived(flow.rules?.forceDeleteAfterFirstDownload === true);
  const levelCap = $derived(flow.levelDownloadsCap);
  const downloadsCap = $derived(maxDownloadsCap(flow.rules));

  function setPassword(on: boolean): void {
    flow.setPasswordOn(on);
    if (!on) {
      showPassword = false;
    }
  }
</script>

<Disclosure
  summary={t('deposit.form.security.title')}
  count={count > 0 ? t('deposit.form.security.count', { count }) : undefined}
  headingLevel={2}
  id="tt-deposit-security"
  bind:open
>
  <div class="tt-security">
    <div class="tt-security__option">
      <Switch
        id={SWITCH_IDS.password}
        label={t('deposit.form.password.switch')}
        checked={flow.passwordEnabled}
        locked={flow.passwordRequired ? t('deposit.form.security.lockedByLevel') : undefined}
        error={flow.passwordEnabled ? undefined : say(errors['password'])}
        onchange={setPassword}
      />
      {#if flow.passwordEnabled}
        <TextField
          id={FIELD_IDS.password}
          label={t('deposit.form.password.label')}
          type={showPassword ? 'text' : 'password'}
          autocomplete="new-password"
          required
          hint={t('deposit.form.password.switchHint')}
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
      {/if}
    </div>

    {#if flow.recipientVerificationOffered}
      <div class="tt-security__option">
        <Switch
          id={FIELD_IDS.recipientVerification}
          label={t('deposit.form.recipientVerification.label')}
          checked={flow.recipientVerificationEffective}
          locked={verificationForced
            ? t('deposit.form.recipientVerification.forced')
            : linkOnlyOn
              ? t('deposit.form.recipientVerification.incompatibleLinkOnly')
              : undefined}
          hint={t('deposit.form.recipientVerification.hint')}
          error={say(errors['recipientVerification'])}
          onchange={(on) => (flow.form.recipientVerification = on)}
        />
      </div>
    {/if}

    <div class="tt-security__option">
      <Switch
        id="tt-deposit-delete-after-first"
        label={t('deposit.form.deleteAfterFirstDownload.label')}
        checked={flow.deleteAfterFirstEffective}
        locked={deleteForced ? t('deposit.form.deleteAfterFirstDownload.forced') : undefined}
        hint={t('deposit.form.deleteAfterFirstDownload.hint')}
        onchange={(on) => (flow.form.deleteAfterFirstDownload = on)}
      />
    </div>

    {#if flow.maxDownloadsOffered}
      <div class="tt-security__option">
        <Switch
          id={SWITCH_IDS.maxDownloads}
          label={t('deposit.form.maxDownloads.switch')}
          checked={flow.maxDownloadsEnabled}
          locked={levelCap === undefined
            ? undefined
            : t('deposit.form.maxDownloads.cappedByLevel', { count: levelCap })}
          hint={t('deposit.form.maxDownloads.switchHint')}
          error={flow.maxDownloadsEnabled ? undefined : say(errors['maxDownloads'])}
          onchange={(on) => flow.setMaxDownloadsOn(on)}
        />
        {#if flow.maxDownloadsEnabled}
          <TextField
            id={FIELD_IDS.maxDownloads}
            label={t('deposit.form.maxDownloads.label')}
            type="number"
            inputmode="numeric"
            min={1}
            max={downloadsCap}
            required={levelCap === undefined}
            hint={levelCap === undefined
              ? t('deposit.form.maxDownloads.fieldHint', { max: downloadsCap })
              : t('deposit.form.maxDownloads.capHint', { max: levelCap })}
            error={say(errors['maxDownloads'])}
            bind:value={flow.form.maxDownloadsText}
          />
        {/if}
      </div>
    {/if}

    {#if flow.e2eOffered}
      <div class="tt-security__option">
        <Switch
          id={FIELD_IDS.endToEnd}
          label={t('deposit.e2e.label')}
          checked={flow.e2eEffective}
          locked={flow.e2eRequired ? t('deposit.e2e.locked') : undefined}
          hint={t('deposit.e2e.hint')}
          error={say(errors['endToEnd'])}
          onchange={(on) => (flow.form.endToEnd = on)}
        />
      </div>
    {/if}
  </div>
</Disclosure>

<style>
  .tt-security__option {
    padding: var(--tt-space-2) 0;
    border-top: var(--tt-border-width) solid var(--tt-separator);
  }

  .tt-security__option:first-child {
    border-top: 0;
  }

  /* The revealed field sits under its switch. */
  .tt-security__option :global(.tt-field) {
    margin: var(--tt-space-2) 0 var(--tt-space-1);
  }
</style>
