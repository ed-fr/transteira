<script lang="ts">
  // My account (CLAUDE.md section 6.5):
  // - profile (username, email, role, entities, two-factor status);
  // - password change (PUT /admin/me/password): the other sessions are closed, this one stays;
  // - new authentication device: current password (POST /admin/me/totp), new secret to
  //   confirm (TotpEnroll), then the new recovery codes, all local to this screen;
  // - disabling two-factor authentication, offered to a delegated admin who has it enabled
  //   (DELETE /admin/me/totp after a confirmation with the current password); the server
  //   refuses it (403) when the account requires it.
  // Secrets (passwords, TOTP secret, recovery codes) stay in this component's memory and are
  // cleared when it goes away or when the session ends (threat model T-162).
  import { onDestroy, tick } from 'svelte';
  import { describeError } from '../../shared/api/problem';
  import { Alert, Button, announce } from '../../shared/components';
  import { i18n, t } from '../../shared/i18n/i18n.svelte';
  import { adminApi, adminSession } from '../api';
  import type { TotpEnrollment } from '../auth/machine';
  import {
    currentPasswordError,
    currentPasswordFailure,
    renderMessage,
    summaryEntries,
    validatePasswordChange,
    type FormFailure,
  } from '../auth/views';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import FormSection from '../components/FormSection.svelte';
  import { errorFor, type SubmitOutcome, type SummaryError } from '../components/form';
  import PasswordField from '../components/PasswordField.svelte';
  import RecoveryCodes from '../components/RecoveryCodes.svelte';
  import TotpEnroll from '../components/TotpEnroll.svelte';
  import { roleKey } from '../shell';
  import type { AdminScreenProps } from './types';

  let { nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids = {
    current: `${uid}-current`,
    password: `${uid}-new`,
    confirm: `${uid}-confirm`,
    reenroll: `${uid}-reenroll-password`,
    disable: `${uid}-disable-password`,
  };

  const me = $derived(adminSession.me);
  const canDisable = $derived(me?.role === 'delegated_admin' && me.totpEnabled);

  // ---- Password change ----
  let current = $state('');
  let password = $state('');
  let confirm = $state('');
  let passwordErrors = $state<SummaryError[]>([]);

  const passwordFields = $derived([
    { name: 'current', id: ids.current, label: t('adminAuth.account.password.current') },
    { name: 'password', id: ids.password, label: t('adminAuth.account.password.new') },
    { name: 'confirm', id: ids.confirm, label: t('adminAuth.password.confirm') },
  ]);

  function failureMessage(failure: FormFailure): string | undefined {
    return renderMessage(failure.general, t);
  }

  async function changePassword(): Promise<SubmitOutcome> {
    try {
      await adminApi.put('/admin/me/password', { body: { currentPassword: current, newPassword: password } });
    } catch (err) {
      const failure = currentPasswordFailure(describeError(i18n, err), 'password');
      const errors = summaryEntries(failure.fields, passwordFields, t);
      current = '';
      const message = failureMessage(failure);
      return message === undefined ? { ok: false, errors } : { ok: false, errors, message };
    }
    current = '';
    password = '';
    confirm = '';
    return { ok: true, message: t('adminAuth.account.password.success') };
  }

  // ---- New authentication device ----
  type EnrollPhase = 'idle' | 'password' | 'enroll' | 'codes';
  let phase = $state<EnrollPhase>('idle');
  let reenrollPassword = $state('');
  let reenrollError = $state<string | undefined>(undefined);
  let reenrollGeneral = $state<string | undefined>(undefined);
  let reenrollBusy = $state(false);
  let enrollment = $state.raw<TotpEnrollment | undefined>(undefined);
  let codes = $state.raw<string[]>([]);
  let totpMessage = $state('');

  async function openReenroll(): Promise<void> {
    totpMessage = '';
    reenrollGeneral = undefined;
    reenrollError = undefined;
    phase = 'password';
    await tick();
    document.getElementById(ids.reenroll)?.focus();
  }

  function closeReenroll(): void {
    phase = 'idle';
    reenrollPassword = '';
    enrollment = undefined;
    codes = [];
  }

  async function startReenroll(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (reenrollBusy) {
      return;
    }
    reenrollGeneral = undefined;
    reenrollError = renderMessage(currentPasswordError(reenrollPassword), t);
    if (reenrollError !== undefined) {
      document.getElementById(ids.reenroll)?.focus();
      return;
    }
    reenrollBusy = true;
    try {
      const res = await adminApi.post('/admin/me/totp', { body: { currentPassword: reenrollPassword } });
      enrollment = res.data;
      phase = 'enroll';
    } catch (err) {
      const failure = currentPasswordFailure(describeError(i18n, err), 'reenroll');
      reenrollError = renderMessage(failure.fields['reenroll'], t);
      reenrollGeneral = failureMessage(failure);
      if (reenrollError !== undefined) {
        await tick();
        document.getElementById(ids.reenroll)?.focus();
      }
    } finally {
      reenrollPassword = '';
      reenrollBusy = false;
    }
  }

  async function confirmReenroll(code: string): Promise<void> {
    const res = await adminApi.post('/admin/me/totp/confirm', { body: { code } });
    enrollment = undefined;
    codes = res.data.recoveryCodes;
    phase = 'codes';
    await adminSession.refreshMe().catch(() => undefined);
  }

  async function restartReenroll(): Promise<void> {
    // The pending secret expired: a new one needs the current password again.
    enrollment = undefined;
    reenrollGeneral = t('adminAuth.enroll.expired');
    phase = 'password';
    await tick();
    document.getElementById(ids.reenroll)?.focus();
  }

  function codesSaved(): void {
    closeReenroll();
    totpMessage = t('adminAuth.enroll.success');
  }

  // ---- Disable two-factor authentication ----
  let disableOpen = $state(false);
  let disablePassword = $state('');

  async function disableTotp(): Promise<string | void> {
    const missing = renderMessage(currentPasswordError(disablePassword), t);
    if (missing !== undefined) {
      document.getElementById(ids.disable)?.focus();
      return missing;
    }
    try {
      await adminApi.delete('/admin/me/totp', { body: { currentPassword: disablePassword } });
    } catch (err) {
      const failure = currentPasswordFailure(describeError(i18n, err), 'disable');
      disablePassword = '';
      return renderMessage(failure.fields['disable'], t) ?? failureMessage(failure) ?? t('errors.unknown');
    }
    disablePassword = '';
    await adminSession.refreshMe().catch(() => undefined);
    totpMessage = t('adminAuth.account.totp.disable.success');
    announce(totpMessage);
  }

  function clearSecrets(): void {
    current = '';
    password = '';
    confirm = '';
    reenrollPassword = '';
    disablePassword = '';
    enrollment = undefined;
    codes = [];
    phase = 'idle';
  }

  const removeResetListener = adminSession.onReset(clearSecrets);

  onDestroy(() => {
    removeResetListener();
    clearSecrets();
  });
</script>

<h1 tabindex="-1">{t('adminAuth.account.title')}</h1>

{#if me}
  <section aria-labelledby="{uid}-profile">
    <h2 id="{uid}-profile">{t('adminAuth.account.profile.title')}</h2>
    <dl class="tt-dl">
      <dt>{t('adminAuth.account.profile.username')}</dt>
      <dd class="tt-break">{me.username}</dd>
      <dt>{t('adminAuth.account.profile.email')}</dt>
      <dd class="tt-break">{me.email}</dd>
      <dt>{t('adminAuth.account.profile.role')}</dt>
      <dd>{t(roleKey(me.role))}</dd>
      <dt>{t('adminAuth.account.profile.tenants')}</dt>
      <dd>
        {#if me.role === 'super_admin'}
          {t('adminAuth.account.profile.allTenants')}
        {:else if me.tenants.length === 0}
          {t('admin.common.none')}
        {:else}
          <ul class="tt-list-plain">
            {#each me.tenants as tenant (tenant.id)}
              <li class="tt-break">{tenant.name} ({tenant.fqdn})</li>
            {/each}
          </ul>
        {/if}
      </dd>
    </dl>
  </section>

  <FormSection
    title={t('adminAuth.account.password.title')}
    intro={t('adminAuth.account.password.otherSessions')}
    validate={() => summaryEntries(validatePasswordChange(current, password, confirm), passwordFields, t)}
    onsubmit={changePassword}
    bind:errors={passwordErrors}
    saveLabel={t('adminAuth.account.password.submit')}
    savingLabel={t('adminAuth.account.password.submitting')}
    successMessage={t('adminAuth.account.password.success')}
  >
    <PasswordField
      id={ids.current}
      label={t('adminAuth.account.password.current')}
      autocomplete="current-password"
      maxlength={1024}
      required
      error={errorFor(passwordErrors, ids.current)}
      bind:value={current}
    />
    <PasswordField
      id={ids.password}
      label={t('adminAuth.account.password.new')}
      hint={t('adminAuth.password.rules')}
      autocomplete="new-password"
      maxlength={1024}
      required
      error={errorFor(passwordErrors, ids.password)}
      bind:value={password}
      confirmLabel={t('adminAuth.password.confirm')}
      confirmId={ids.confirm}
      confirmError={errorFor(passwordErrors, ids.confirm)}
      bind:confirmValue={confirm}
    />
  </FormSection>

  <section aria-labelledby="{uid}-totp">
    <h2 id="{uid}-totp">{t('adminAuth.account.totp.title')}</h2>
    <p>
      {t('adminAuth.account.totp.status', {
        status: me.totpEnabled ? t('adminAuth.account.totp.enabled') : t('adminAuth.account.totp.disabled'),
      })}
    </p>
    {#if totpMessage !== ''}
      <Alert severity="success">{totpMessage}</Alert>
    {/if}

    {#if phase === 'enroll'}
      <TotpEnroll
        {enrollment}
        headingLevel={3}
        onconfirm={confirmReenroll}
        onrestart={restartReenroll}
        oncancel={closeReenroll}
      />
    {:else if phase === 'codes'}
      <RecoveryCodes
        {codes}
        username={me.username}
        headingLevel={3}
        addGuard={(guard) => nav.addGuard(guard)}
        oncontinue={codesSaved}
      />
    {:else}
      <h3>{t('adminAuth.account.totp.reenroll.title')}</h3>
      <p>{t('adminAuth.account.totp.reenroll.text')}</p>
      {#if phase === 'password'}
        {#if reenrollGeneral !== undefined}
          <Alert severity="error">{reenrollGeneral}</Alert>
        {/if}
        <form class="tt-stack" novalidate onsubmit={startReenroll}>
          <PasswordField
            id={ids.reenroll}
            label={t('adminAuth.account.totp.currentPassword')}
            hint={t('adminAuth.account.totp.reenroll.confirmText')}
            autocomplete="current-password"
            maxlength={1024}
            required
            error={reenrollError}
            bind:value={reenrollPassword}
          />
          <div class="tt-cluster">
            <Button type="submit" loading={reenrollBusy}>
              {me.totpEnabled
                ? t('adminAuth.account.totp.reenroll.action')
                : t('adminAuth.account.totp.reenroll.enableAction')}
            </Button>
            <Button variant="secondary" disabled={reenrollBusy} onclick={closeReenroll}>
              {t('admin.common.cancel')}
            </Button>
          </div>
        </form>
      {:else}
        <Button variant="secondary" onclick={() => void openReenroll()}>
          {me.totpEnabled
            ? t('adminAuth.account.totp.reenroll.action')
            : t('adminAuth.account.totp.reenroll.enableAction')}
        </Button>
      {/if}

      {#if canDisable}
        <h3>{t('adminAuth.account.totp.disable.title')}</h3>
        <p>{t('adminAuth.account.totp.disable.text')}</p>
        <Button
          variant="danger"
          onclick={() => {
            totpMessage = '';
            disablePassword = '';
            disableOpen = true;
          }}
        >
          {t('adminAuth.account.totp.disable.action')}
        </Button>
      {/if}
    {/if}
  </section>

  <ConfirmDialog
    bind:open={disableOpen}
    title={t('adminAuth.account.totp.disable.confirmTitle')}
    text={t('adminAuth.account.totp.disable.text')}
    confirmLabel={t('adminAuth.account.totp.disable.action')}
    danger
    onconfirm={disableTotp}
    onclose={() => {
      disablePassword = '';
    }}
  >
    <PasswordField
      id={ids.disable}
      label={t('adminAuth.account.totp.currentPassword')}
      hint={t('adminAuth.account.totp.disable.confirmText')}
      autocomplete="current-password"
      maxlength={1024}
      required
      bind:value={disablePassword}
    />
  </ConfirmDialog>
{/if}
