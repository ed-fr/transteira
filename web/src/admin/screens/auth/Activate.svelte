<script lang="ts">
  // Account activation from the link of a super admin (/admin/activate#act_…, threat model
  // T-162). The entry point (main.ts) reads the token from the fragment and removes the fragment
  // from the address bar and the history entry (history.replaceState) before the bootstrap; this
  // screen takes it once, and the token then only lives in its memory until it is used. A missing, malformed, used or expired
  // token shows "invalid link". The admin chooses a password, then the step the server asks for
  // follows (TOTP enrollment and recovery codes, or second factor), then the home page.
  import { onDestroy, onMount, tick } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, Spinner, announce } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminSession } from '../../api';
  import { takeActivationToken } from '../../auth/activationToken';
  import { createFormState } from '../../auth/formState.svelte';
  import type { TotpCode } from '../../auth/session.svelte';
  import {
    activationFailure,
    flowView,
    renderMessage,
    summaryEntries,
    validateNewPassword,
  } from '../../auth/views';
  import PasswordField from '../../components/PasswordField.svelte';
  import RecoveryCodes from '../../components/RecoveryCodes.svelte';
  import TotpEnroll from '../../components/TotpEnroll.svelte';
  import TotpStep from '../../components/TotpStep.svelte';
  import { cleanActivationUrl, readActivationToken } from '../../forms/activation';
  import type { AdminScreenProps } from '../types';
  import ErrorSummary from './ErrorSummary.svelte';

  let { nav }: AdminScreenProps = $props();

  /**
   * Fallback when the entry point captured nothing (the screen reached without a reload): reads
   * the token of the fragment, then removes the fragment from the URL and the history.
   */
  function tokenFromLocation(): string | null {
    const location = globalThis.location;
    if (location === undefined || location.hash === '') {
      return null;
    }
    const value = readActivationToken(location.hash);
    globalThis.history.replaceState(globalThis.history.state, '', cleanActivationUrl(location));
    return value;
  }

  // Not reactive on purpose: the token never reaches the DOM. main.ts captured it from the
  // fragment before the bootstrap (auth/activationToken.ts); it is taken once.
  let token: string | null = takeActivationToken() ?? tokenFromLocation();
  // Back here once signed in (the screen is re-created after the profile is loaded): home.
  const leaving = token === null && adminSession.state.kind === 'authenticated';
  onMount(() => {
    if (leaving) {
      void nav.navigate('/', { replace: true });
    }
  });

  const uid = $props.id();
  const ids = { password: `${uid}-password`, confirm: `${uid}-confirm` };
  const form = createFormState({ announce: (m) => announce(renderMessage(m, t) ?? '', 'assertive') });
  let invalidLink = $state(token === null);
  let password = $state('');
  let confirm = $state('');
  let heading: HTMLHeadingElement | undefined = $state();

  const view = $derived(flowView(adminSession.state, 'activation'));
  const general = $derived(renderMessage(form.general, t));
  const fieldList = $derived([
    { name: 'password', id: ids.password, label: t('adminAuth.activation.password.label') },
    { name: 'confirm', id: ids.confirm, label: t('adminAuth.password.confirm') },
  ]);
  const summary = $derived(summaryEntries(form.fields, fieldList, t));

  function goHomeWhenDone(): void {
    if (adminSession.state.kind === 'authenticated') {
      void nav.navigate('/', { replace: true });
    }
  }

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (form.blocked || token === null) {
      return;
    }
    if (!form.check(validateNewPassword(password, confirm))) {
      await tick();
      document.getElementById(form.fields['password'] ? ids.password : ids.confirm)?.focus();
      return;
    }
    form.busy = true;
    try {
      await adminSession.activate({ activationToken: token, password });
      token = null;
      password = '';
      confirm = '';
      form.clear();
      goHomeWhenDone();
    } catch (err) {
      const failure = activationFailure(describeError(i18n, err));
      if (failure.invalidLink === true) {
        token = null;
        password = '';
        confirm = '';
        invalidLink = true;
        await tick();
        heading?.focus();
      } else {
        form.fail(failure);
      }
    } finally {
      form.busy = false;
    }
  }

  async function verify(body: TotpCode): Promise<void> {
    await adminSession.verifyTotp(body);
    goHomeWhenDone();
  }

  async function finish(): Promise<void> {
    await adminSession.acknowledgeCodes();
    goHomeWhenDone();
  }

  async function backToLogin(): Promise<void> {
    try {
      await adminSession.logout();
    } catch {
      // Server unreachable: the pre-auth session expires on its own; nothing stays in memory.
      adminSession.endLocally();
    }
    await nav.navigate('/login');
  }

  onDestroy(() => {
    token = null;
    password = '';
    confirm = '';
    form.dispose();
  });
</script>

{#if leaving}
  <p><Spinner showLabel label={t('admin.loading')} /></p>
{:else if view.kind === 'totp'}
  <TotpStep onverify={verify} oncancel={() => void backToLogin()} />
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
    username={view.username}
    addGuard={(guard) => nav.addGuard(guard)}
    oncontinue={finish}
  />
{:else if view.kind === 'unsupported'}
  <h1 tabindex="-1">{t('admin.unsupportedStep.title')}</h1>
  <p>{t('admin.unsupportedStep.text')}</p>
  <Button onclick={() => void backToLogin()}>{t('admin.unsupportedStep.action')}</Button>
{:else if view.kind === 'loading'}
  <p><Spinner showLabel label={t('admin.loading')} /></p>
{:else if invalidLink}
  <h1 tabindex="-1" bind:this={heading}>{t('adminAuth.activation.invalidLink.title')}</h1>
  <Alert severity="error" live={false}>
    <p>{t('adminAuth.activation.invalidLink.text')}</p>
  </Alert>
  <p><a href={nav.href('/login')} use:nav.link>{t('adminAuth.activation.goToLogin')}</a></p>
{:else}
  <h1 tabindex="-1">{t('adminAuth.activation.title')}</h1>
  <p>{t('adminAuth.activation.intro')}</p>
  <ErrorSummary entries={summary} />
  {#if general !== undefined}
    <Alert severity="error" live={!form.locked}>{general}</Alert>
  {/if}
  <form class="tt-stack" novalidate onsubmit={submit}>
    <PasswordField
      id={ids.password}
      label={t('adminAuth.activation.password.label')}
      hint={t('adminAuth.password.rules')}
      autocomplete="new-password"
      maxlength={1024}
      required
      error={renderMessage(form.fields['password'], t)}
      bind:value={password}
      confirmLabel={t('adminAuth.password.confirm')}
      confirmId={ids.confirm}
      confirmError={renderMessage(form.fields['confirm'], t)}
      bind:confirmValue={confirm}
    />
    <div>
      <Button
        type="submit"
        loading={form.busy}
        loadingLabel={t('adminAuth.activation.submitting')}
        disabled={form.remaining > 0}
      >
        {t('adminAuth.activation.submit')}
      </Button>
    </div>
  </form>
{/if}
