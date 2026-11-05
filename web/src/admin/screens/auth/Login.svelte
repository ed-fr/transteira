<script lang="ts">
  // Sign-in (CLAUDE.md section 6.5): username and password, then, in the same route, the step
  // the server asks for: second factor (TOTP code or recovery code), mandatory TOTP enrollment
  // followed by the recovery codes, or a step this version cannot handle. A wrong username or
  // password gives one generic message that never tells whether the account exists; a lock
  // (429) counts down. The flash message of the session (expired, signed out) is shown until the
  // first submission.
  // Single sign-on (since 2.0): when GET /admin/auth/methods says it is available, a second form
  // asks for the e-mail address and sends the browser to the identity provider (the URL is only
  // followed when it is https). The callback comes back here with ?error=<code>: only the
  // codes of a closed list are translated, any other value gives a generic message.
  // Once authenticated, the navigation guard goes to the return path (safeNext of ?next=).
  import { onDestroy, onMount, tick } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, Spinner, TextField, announce } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi, adminSession } from '../../api';
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
  import { isSafeRedirectUrl, ssoEmailError, ssoLoginErrorKey, ssoStartFailure } from '../../auth/sso';
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
  const ids = { username: `${uid}-username`, password: `${uid}-password`, ssoEmail: `${uid}-sso-email` };
  const form = createFormState({ announce: (m) => announce(renderMessage(m, t) ?? '', 'assertive') });
  let username = $state('');
  let password = $state('');
  let heading: HTMLHeadingElement | undefined = $state();
  let previous: FlowView['kind'] | undefined;
  // Set by the first submission: the flash message of the session (e.g. "signed out") then
  // gives way to the result of the attempt.
  let attempted = $state(false);
  let ssoAvailable = $state(false);
  let ssoEmail = $state('');
  const ssoForm = createFormState({ announce: (m) => announce(renderMessage(m, t) ?? '', 'assertive') });

  const view = $derived(flowView(adminSession.state, 'login'));
  const flash = $derived<AuthFlash | undefined>(
    adminSession.state.kind === 'anonymous' && !attempted ? adminSession.state.flash : undefined,
  );
  const general = $derived(renderMessage(form.general, t));
  const ssoGeneral = $derived(renderMessage(ssoForm.general, t));
  // Message of the ?error= parameter of the callback, shown until a new attempt.
  const callbackErrorKey = $derived(attempted ? undefined : ssoLoginErrorKey(nav.current.search));
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

  async function startSso(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (ssoForm.blocked) {
      return;
    }
    attempted = true;
    if (!ssoForm.check({ email: ssoEmailError(ssoEmail) })) {
      await tick();
      document.getElementById(ids.ssoEmail)?.focus();
      return;
    }
    ssoForm.busy = true;
    try {
      const res = await adminApi.post('/admin/auth/oidc/start', { body: { email: ssoEmail.trim() } });
      const url = res.data.redirectUrl;
      if (!isSafeRedirectUrl(url)) {
        ssoForm.fail({ general: { key: 'adminAuth.sso.badRedirect' }, fields: {} });
        return;
      }
      ssoForm.clear();
      globalThis.location.assign(url);
    } catch (err) {
      ssoForm.fail(ssoStartFailure(describeError(i18n, err)));
    } finally {
      ssoForm.busy = false;
    }
  }

  async function loadMethods(): Promise<void> {
    try {
      const res = await adminApi.get('/admin/auth/methods');
      ssoAvailable = res.data.sso;
    } catch {
      // The password form always works: without the answer, the single sign-on is not offered.
      ssoAvailable = false;
    }
  }

  onMount(() => {
    void loadMethods();
  });

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
    ssoForm.dispose();
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
  {#if callbackErrorKey !== undefined}
    <Alert severity="error"><p>{t(callbackErrorKey)}</p></Alert>
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
  {#if ssoAvailable}
    <section class="tt-sso" aria-labelledby="{uid}-sso-title">
      <h2 id="{uid}-sso-title">{t('adminAuth.sso.title')}</h2>
      <p>{t('adminAuth.sso.intro')}</p>
      {#if ssoGeneral !== undefined}
        <Alert severity="error" live={!ssoForm.locked}>{ssoGeneral}</Alert>
      {/if}
      <form class="tt-stack" novalidate onsubmit={startSso}>
        <TextField
          id={ids.ssoEmail}
          type="email"
          label={t('adminAuth.sso.email.label')}
          hint={t('adminAuth.sso.email.hint')}
          autocomplete="email"
          autocapitalize="off"
          spellcheck={false}
          maxlength={254}
          required
          error={renderMessage(ssoForm.fields['email'], t)}
          bind:value={ssoEmail}
        />
        <div>
          <Button
            type="submit"
            variant="secondary"
            loading={ssoForm.busy}
            loadingLabel={t('adminAuth.sso.submitting')}
            disabled={ssoForm.remaining > 0}
          >
            {t('adminAuth.sso.submit')}
          </Button>
        </div>
      </form>
    </section>
  {/if}
{/if}

<style>
  .tt-sso {
    margin-top: var(--tt-space-6);
    padding-top: var(--tt-space-4);
    border-top: var(--tt-border-width) solid var(--tt-border);
  }
</style>
