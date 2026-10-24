<script lang="ts">
  // First-run setup (CLAUDE.md section 6.6): creation of the super admin with the setup token
  // (TT_SETUP_TOKEN, TT_SETUP_TOKEN_FILE, or the token written to the application log), then
  // the mandatory TOTP enrollment with the secret of the 201 answer, then the recovery codes.
  // Errors: an invalid token is shown on its field, a setup already done sends to sign-in, a
  // lock (429) counts down. Once the codes are acknowledged, the navigation guard goes home.
  import { onDestroy, tick } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, Spinner, TextField, announce } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminSession } from '../../api';
  import { createFormState } from '../../auth/formState.svelte';
  import { flowView, renderMessage, setupFailure, summaryEntries, validateSetup } from '../../auth/views';
  import PasswordField from '../../components/PasswordField.svelte';
  import RecoveryCodes from '../../components/RecoveryCodes.svelte';
  import TotpEnroll from '../../components/TotpEnroll.svelte';
  import type { AdminScreenProps } from '../types';
  import ErrorSummary from './ErrorSummary.svelte';

  let { nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids = {
    username: `${uid}-username`,
    email: `${uid}-email`,
    password: `${uid}-password`,
    confirm: `${uid}-confirm`,
    setupToken: `${uid}-token`,
  };
  const form = createFormState({ announce: (m) => announce(renderMessage(m, t) ?? '', 'assertive') });
  let username = $state('');
  let email = $state('');
  let password = $state('');
  let confirm = $state('');
  let setupToken = $state('');
  let alreadyDone = $state(false);

  const view = $derived(flowView(adminSession.state, 'setup'));
  const general = $derived(renderMessage(form.general, t));
  const fieldList = $derived([
    { name: 'username', id: ids.username, label: t('adminAuth.setup.username.label') },
    { name: 'email', id: ids.email, label: t('adminAuth.setup.email.label') },
    { name: 'password', id: ids.password, label: t('adminAuth.setup.password.label') },
    { name: 'confirm', id: ids.confirm, label: t('adminAuth.password.confirm') },
    { name: 'setupToken', id: ids.setupToken, label: t('adminAuth.setup.setupToken.label') },
  ]);
  const summary = $derived(summaryEntries(form.fields, fieldList, t));
  const err = (name: string): string | undefined => renderMessage(form.fields[name], t);

  async function focusFirstError(): Promise<void> {
    await tick();
    const first = fieldList.find((f) => form.fields[f.name] !== undefined);
    if (first !== undefined) {
      document.getElementById(first.id)?.focus();
    }
  }

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (form.blocked || alreadyDone) {
      return;
    }
    if (!form.check(validateSetup({ username, email, password, confirm, setupToken }))) {
      await focusFirstError();
      return;
    }
    form.busy = true;
    try {
      await adminSession.setup({
        username: username.trim(),
        email: email.trim(),
        password,
        setupToken: setupToken.trim(),
      });
      form.clear();
      password = '';
      confirm = '';
      setupToken = '';
      announce(t('adminAuth.setup.nextStep'));
    } catch (e) {
      const failure = setupFailure(describeError(i18n, e));
      form.fail(failure);
      alreadyDone = failure.redirect === 'login';
      await focusFirstError();
    } finally {
      form.busy = false;
    }
  }

  async function finish(): Promise<void> {
    await adminSession.acknowledgeCodes();
    announce(t('adminAuth.setup.done'));
  }

  function goToLogin(): void {
    // The setup is done: the machine leaves the setup state, the guard opens the sign-in.
    adminSession.dispatch({ type: 'SETUP_STATUS', setupRequired: false });
  }

  onDestroy(() => {
    password = '';
    confirm = '';
    setupToken = '';
    form.dispose();
  });
</script>

{#if view.kind === 'enroll' || view.kind === 'enrollStart'}
  <TotpEnroll
    enrollment={view.kind === 'enroll' ? view.enrollment : undefined}
    required
    preauth
    onconfirm={(code) => adminSession.confirmEnrollment(code)}
    onrestart={() => adminSession.startEnrollment()}
  />
{:else if view.kind === 'recovery'}
  <RecoveryCodes
    codes={view.codes}
    username={view.username ?? username.trim()}
    addGuard={(guard) => nav.addGuard(guard)}
    oncontinue={finish}
  />
{:else if view.kind === 'form'}
  <h1 tabindex="-1">{t('adminAuth.setup.title')}</h1>
  <p>{t('adminAuth.setup.intro')}</p>
  <ErrorSummary entries={summary} />
  {#if general !== undefined}
    <Alert severity="error" live={!form.locked}>{general}</Alert>
  {/if}
  {#if alreadyDone}
    <p><Button onclick={goToLogin}>{t('adminAuth.activation.goToLogin')}</Button></p>
  {:else}
    <form class="tt-stack" novalidate onsubmit={submit}>
      <TextField
        id={ids.username}
        label={t('adminAuth.setup.username.label')}
        hint={t('adminAuth.setup.username.hint')}
        autocomplete="username"
        autocapitalize="off"
        spellcheck={false}
        maxlength={64}
        required
        error={err('username')}
        bind:value={username}
      />
      <TextField
        id={ids.email}
        type="email"
        label={t('adminAuth.setup.email.label')}
        hint={t('adminAuth.setup.email.hint')}
        autocomplete="email"
        spellcheck={false}
        required
        error={err('email')}
        bind:value={email}
      />
      <PasswordField
        id={ids.password}
        label={t('adminAuth.setup.password.label')}
        hint={t('adminAuth.password.rules')}
        autocomplete="new-password"
        maxlength={1024}
        required
        error={err('password')}
        bind:value={password}
        confirmLabel={t('adminAuth.password.confirm')}
        confirmId={ids.confirm}
        confirmError={err('confirm')}
        bind:confirmValue={confirm}
      />
      <PasswordField
        id={ids.setupToken}
        label={t('adminAuth.setup.setupToken.label')}
        hint={t('adminAuth.setup.setupToken.hint')}
        autocomplete="off"
        maxlength={128}
        required
        error={err('setupToken')}
        bind:value={setupToken}
      />
      <div>
        <Button
          type="submit"
          loading={form.busy}
          loadingLabel={t('adminAuth.setup.submitting')}
          disabled={form.remaining > 0}
        >
          {t('adminAuth.setup.submit')}
        </Button>
      </div>
    </form>
  {/if}
{:else}
  <p><Spinner showLabel label={t('admin.loading')} /></p>
{/if}
