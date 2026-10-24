<script lang="ts">
  // Sign-in (CLAUDE.md section 6.5): username and password, then, in the same route, the step
  // the server asks for: second factor (TOTP code or recovery code), mandatory TOTP enrollment
  // followed by the recovery codes, or a step this version cannot handle. A wrong username or
  // password gives one generic message that never tells whether the account exists; a lock
  // (429) counts down. The flash message of the session (expired, signed out) is shown until the
  // first submission.
  // Once authenticated, the navigation guard goes to the return path (safeNext of ?next=).
  import { onDestroy, tick } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, Spinner, TextField, announce } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminSession } from '../../api';
  import { createFormState } from '../../auth/formState.svelte';
  import type { AuthFlash } from '../../auth/machine';
  import {
    flowView,
    loginFailure,
    renderMessage,
    summaryEntries,
    validateLogin,
    type FlowView,
  } from '../../auth/views';
  import PasswordField from '../../components/PasswordField.svelte';
  import RecoveryCodes from '../../components/RecoveryCodes.svelte';
  import TotpEnroll from '../../components/TotpEnroll.svelte';
  import TotpStep from '../../components/TotpStep.svelte';
  import type { AdminScreenProps } from '../types';
  import ErrorSummary from './ErrorSummary.svelte';

  let { nav }: AdminScreenProps = $props();

  const FLASH_KEYS: Record<AuthFlash, string> = {
    sessionExpired: 'admin.flash.sessionExpired',
    stepExpired: 'admin.flash.stepExpired',
    loggedOut: 'admin.flash.loggedOut',
  };

  const uid = $props.id();
  const ids = { username: `${uid}-username`, password: `${uid}-password` };
  const form = createFormState({ announce: (m) => announce(renderMessage(m, t) ?? '', 'assertive') });
  let username = $state('');
  let password = $state('');
  let heading: HTMLHeadingElement | undefined = $state();
  let previous: FlowView['kind'] | undefined;
  // Set by the first submission: the flash message of the session (e.g. "signed out") then
  // gives way to the result of the attempt.
  let attempted = $state(false);

  const view = $derived(flowView(adminSession.state, 'login'));
  const flash = $derived<AuthFlash | undefined>(
    adminSession.state.kind === 'anonymous' && !attempted ? adminSession.state.flash : undefined,
  );
  const general = $derived(renderMessage(form.general, t));
  const summary = $derived(
    summaryEntries(
      form.fields,
      [
        { name: 'username', id: ids.username, label: t('adminAuth.login.username.label') },
        { name: 'password', id: ids.password, label: t('adminAuth.login.password.label') },
      ],
      t,
    ),
  );

  // Back to the form from a step (cancelled or expired): the focus goes to the heading.
  $effect(() => {
    const kind = view.kind;
    if (kind === 'form' && previous !== undefined && previous !== 'form') {
      void tick().then(() => heading?.focus());
    }
    previous = kind;
  });

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (form.blocked) {
      return;
    }
    attempted = true;
    if (!form.check(validateLogin(username, password))) {
      await tick();
      document.getElementById(form.fields['username'] ? ids.username : ids.password)?.focus();
      return;
    }
    form.busy = true;
    try {
      await adminSession.login({ username: username.trim(), password });
      form.clear();
    } catch (err) {
      form.fail(loginFailure(describeError(i18n, err)));
    } finally {
      password = '';
      form.busy = false;
    }
  }

  async function backToLogin(): Promise<void> {
    try {
      await adminSession.logout();
    } catch {
      // Server unreachable: the pre-auth session expires on its own after 5 minutes; the
      // local state, the CSRF token and the in-memory stores are cleared now.
      adminSession.endLocally();
    }
  }

  onDestroy(() => {
    password = '';
    form.dispose();
  });
</script>

{#if view.kind === 'totp'}
  <TotpStep onverify={(body) => adminSession.verifyTotp(body)} oncancel={() => void backToLogin()} />
{:else if view.kind === 'enrollStart' || view.kind === 'enroll'}
  <TotpEnroll
    enrollment={view.kind === 'enroll' ? view.enrollment : undefined}
    required
    preauth
    onconfirm={(code) => adminSession.confirmEnrollment(code)}
    onrestart={() => adminSession.startEnrollment()}
    oncancel={() => void backToLogin()}
    cancelLabel={t('adminAuth.totp.cancel')}
  />
{:else if view.kind === 'recovery'}
  <RecoveryCodes
    codes={view.codes}
    username={view.username ?? username.trim()}
    addGuard={(guard) => nav.addGuard(guard)}
    oncontinue={() => adminSession.acknowledgeCodes()}
  />
{:else if view.kind === 'unsupported'}
  <h1 tabindex="-1">{t('admin.unsupportedStep.title')}</h1>
  <p>{t('admin.unsupportedStep.text')}</p>
  <Button onclick={() => void backToLogin()}>{t('admin.unsupportedStep.action')}</Button>
{:else if view.kind === 'loading' || view.kind === 'done'}
  <p><Spinner showLabel label={t('admin.loading')} /></p>
{:else}
  <h1 tabindex="-1" bind:this={heading}>{t('adminAuth.login.title')}</h1>
  {#if flash !== undefined}
    <Alert severity={flash === 'loggedOut' ? 'success' : 'warning'}>
      <p>{t(FLASH_KEYS[flash])}</p>
    </Alert>
  {/if}
  <p>{t('adminAuth.login.intro')}</p>
  <ErrorSummary entries={summary} />
  {#if general !== undefined}
    <Alert severity="error" live={!form.locked}>{general}</Alert>
  {/if}
  <form class="tt-stack" novalidate onsubmit={submit}>
    <TextField
      id={ids.username}
      label={t('adminAuth.login.username.label')}
      autocomplete="username"
      autocapitalize="off"
      spellcheck={false}
      maxlength={64}
      required
      error={renderMessage(form.fields['username'], t)}
      bind:value={username}
    />
    <PasswordField
      id={ids.password}
      label={t('adminAuth.login.password.label')}
      autocomplete="current-password"
      maxlength={1024}
      required
      error={renderMessage(form.fields['password'], t)}
      bind:value={password}
    />
    <div>
      <Button
        type="submit"
        loading={form.busy}
        loadingLabel={t('adminAuth.login.submitting')}
        disabled={form.remaining > 0}
      >
        {t('adminAuth.login.submit')}
      </Button>
    </div>
  </form>
  <p class="tt-text-muted tt-text-sm">{t('adminAuth.login.forgotten')}</p>
{/if}
