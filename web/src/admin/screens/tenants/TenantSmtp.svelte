<script lang="ts">
  // Mail settings of a tenant (CLAUDE.md section 12.1):
  // - settings (GET/PUT /admin/tenants/{id}/smtp; 404 when none are saved yet): server, port
  //   with the usual port of the security mode, security, optional username, password kept,
  //   replaced or removed (never returned by the API), sender. The password must be entered
  //   again (or removed) when the server, port or username changes (buildSmtpUpdate), and a
  //   warning says when credentials would travel without encryption;
  // - test send (POST .../smtp/test) with the saved settings: stage reached, duration and server
  //   message shown as text, rate limit (429) handled;
  // - indicative DNS check of the sender domain (GET .../smtp/dns-check): SPF, DKIM (selectors
  //   given by the admin) and DMARC, records and messages shown as text.
  // The tenant sub-navigation is rendered by App.svelte.
  import { ApiProblem } from '../../../shared/api/client';
  import { describeError } from '../../../shared/api/problem';
  import {
    Alert,
    Button,
    HelpIcon,
    RadioGroup,
    Spinner,
    TextField,
    announce,
  } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi, adminSession } from '../../api';
  import FormSection from '../../components/FormSection.svelte';
  import SecretModeField from '../../components/SecretModeField.svelte';
  import StatusBadge from '../../components/StatusBadge.svelte';
  import { errorFor, summaryFromFields, type SubmitOutcome, type SummaryError } from '../../components/form';
  import { parseDkimSelectors } from '../../forms/dkim';
  import {
    SUGGESTED_PORTS,
    portAfterSecurityChange,
    smtpFormFrom,
    type PasswordMode,
    type SmtpSecurity,
    type SmtpSettings,
    usernameWithoutSecurity,
  } from '../../forms/smtp';
  import type { AdminScreenProps } from '../types';
  import {
    dnsCheckPath,
    dnsRows,
    dnsVariant,
    formWithPort,
    parsePort,
    selectorsError,
    smtpDirty,
    testFailureMessage,
    testRecipientError,
    testResultView,
    validateSmtp,
    type DnsRow,
    type MailDnsCheck,
    type SmtpFields,
    type TestResultView,
  } from './smtpScreen';

  const { params, nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids = {
    host: `${uid}-host`,
    port: `${uid}-port`,
    security: `${uid}-security`,
    username: `${uid}-username`,
    password: `${uid}-password`,
    fromAddress: `${uid}-from-address`,
    fromName: `${uid}-from-name`,
    to: `${uid}-to`,
    selectors: `${uid}-selectors`,
  };
  const tenantId = $derived(params['id'] ?? '');

  // ---- Settings ----
  let loading = $state(true);
  let loadError = $state('');
  let stored = $state.raw<SmtpSettings | null>(null);
  let host = $state('');
  let portText = $state('');
  let security = $state<SmtpSecurity>('starttls');
  let username = $state('');
  let passwordMode = $state<PasswordMode>('keep');
  let password = $state('');
  let fromAddress = $state('');
  let fromName = $state('');
  let errors = $state<SummaryError[]>([]);

  const form = $derived(
    formWithPort({ host, security, username, passwordMode, password, fromAddress, fromName }, portText),
  );
  const dirty = $derived(!loading && smtpDirty(stored, form));
  const suggestedPort = $derived(SUGGESTED_PORTS[security]);
  const insecure = $derived(usernameWithoutSecurity(form));
  const fields: SmtpFields = $derived({
    host: { id: ids.host, label: t('adminTenants.smtp.host.label') },
    port: { id: ids.port, label: t('adminTenants.smtp.port.label') },
    security: { id: ids.security, label: t('adminTenants.smtp.security.label') },
    username: { id: ids.username, label: t('adminTenants.smtp.username.label') },
    password: {
      id: ids.password,
      label:
        stored?.passwordSet === true
          ? t('adminTenants.smtp.password.mode')
          : t('adminTenants.smtp.password.label'),
    },
    fromAddress: { id: ids.fromAddress, label: t('adminTenants.smtp.fromAddress.label') },
    fromName: { id: ids.fromName, label: t('adminTenants.smtp.fromName.label') },
  });
  const securityOptions = $derived([
    {
      value: 'none' as const,
      label: t('adminTenants.smtp.security.none'),
      hint: t('adminTenants.smtp.security.noneHint'),
    },
    { value: 'starttls' as const, label: t('adminTenants.smtp.security.starttls') },
    { value: 'tls' as const, label: t('adminTenants.smtp.security.tls') },
  ]);

  function show(settings: SmtpSettings | null): void {
    stored = settings;
    const f = smtpFormFrom(settings);
    host = f.host;
    portText = String(f.port);
    security = f.security;
    username = f.username;
    passwordMode = f.passwordMode;
    password = f.password;
    fromAddress = f.fromAddress;
    fromName = f.fromName;
  }

  async function load(id: string): Promise<void> {
    loading = true;
    loadError = '';
    try {
      const res = await adminApi.get('/admin/tenants/{tenantId}/smtp', { path: { tenantId: id } });
      show(res.data);
    } catch (err) {
      if (err instanceof ApiProblem && err.status === 404) {
        show(null);
      } else {
        loadError = describeError(i18n, err).message;
      }
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    void load(tenantId);
  });

  function onSecurityChange(value: SmtpSecurity): void {
    const current = parsePort(portText) ?? Number.NaN;
    portText = String(portAfterSecurityChange(current, value));
  }

  function validate(): SummaryError[] {
    const r = validateSmtp(stored, form, fields, t);
    return r.ok ? [] : r.errors;
  }

  async function save(): Promise<SubmitOutcome> {
    const r = validateSmtp(stored, form, fields, t);
    if (!r.ok) {
      return { ok: false, errors: r.errors };
    }
    try {
      const res = await adminApi.put('/admin/tenants/{tenantId}/smtp', {
        path: { tenantId },
        body: r.update,
      });
      show(res.data);
      return { ok: true, message: t('adminTenants.smtp.saved') };
    } catch (err) {
      const view = describeError(i18n, err);
      const mapped = summaryFromFields(view.fields, { ...fields, removePassword: fields.password });
      const message = mapped.errors.length === 0 || mapped.unmatched.length > 0 ? view.message : undefined;
      return message === undefined
        ? { ok: false, errors: mapped.errors }
        : { ok: false, errors: mapped.errors, message };
    }
  }

  // ---- Test send ----
  let to = $state('');
  let toTouched = false;
  let toError = $state<string | undefined>(undefined);
  let testing = $state(false);
  let testResult = $state.raw<TestResultView | undefined>(undefined);
  let testFailure = $state('');

  // The recipient defaults to the address of the signed-in admin, until the admin types one.
  $effect(() => {
    const email = adminSession.me?.email;
    if (!toTouched && email !== undefined && to === '') {
      to = email;
    }
  });

  async function sendTest(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (testing) {
      return;
    }
    testResult = undefined;
    testFailure = '';
    const m = testRecipientError(to);
    toError = m === undefined ? undefined : t(m.key, m.params);
    if (toError !== undefined) {
      document.getElementById(ids.to)?.focus();
      return;
    }
    testing = true;
    try {
      const res = await adminApi.post('/admin/tenants/{tenantId}/smtp/test', {
        path: { tenantId },
        body: { to: to.trim() },
      });
      testResult = testResultView(res.data, t);
    } catch (err) {
      const view = describeError(i18n, err);
      const field = view.fields['to'];
      if (field !== undefined) {
        toError = field.message;
        document.getElementById(ids.to)?.focus();
      } else {
        testFailure = testFailureMessage(view, t);
      }
    } finally {
      testing = false;
    }
  }

  // ---- DNS check ----
  let selectorsText = $state('');
  let selectorsFieldError = $state<string | undefined>(undefined);
  let checking = $state(false);
  let dnsCheck = $state.raw<MailDnsCheck | undefined>(undefined);
  let dnsFailure = $state('');
  let dnsNotConfigured = $state(false);
  const rows: DnsRow[] = $derived(dnsCheck === undefined ? [] : dnsRows(dnsCheck));

  async function checkDns(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (checking) {
      return;
    }
    dnsFailure = '';
    dnsNotConfigured = false;
    const parsed = parseDkimSelectors(selectorsText);
    const m = selectorsError(parsed);
    selectorsFieldError = m === undefined ? undefined : t(m.key, m.params);
    if (selectorsFieldError !== undefined) {
      document.getElementById(ids.selectors)?.focus();
      return;
    }
    checking = true;
    try {
      // The typed client has no array query parameters: the repeated dkimSelector is built here.
      const res = await adminApi.request<MailDnsCheck>('GET', dnsCheckPath(tenantId, parsed.selectors));
      dnsCheck = res.data;
      announce(t('adminTenants.smtp.dns.domain', { domain: res.data.domain }));
    } catch (err) {
      dnsCheck = undefined;
      const view = describeError(i18n, err);
      const field = view.fields['dkimSelector'];
      if (field !== undefined) {
        selectorsFieldError = field.message;
        document.getElementById(ids.selectors)?.focus();
      } else if (view.status === 404) {
        dnsNotConfigured = true;
      } else {
        dnsFailure = view.message;
      }
    } finally {
      checking = false;
    }
  }
</script>

<div class="tt-title-row">
  <h1 tabindex="-1">{t('adminTenants.smtp.title')}</h1>
  <HelpIcon topic="tenant-smtp" title={t('adminTenants.smtp.title')} {nav} />
</div>

{#if loading}
  <p><Spinner showLabel /></p>
{:else if loadError !== ''}
  <Alert severity="error">{loadError}</Alert>
{:else}
  {#if stored === null}
    <Alert severity="info" live={false}>{t('adminTenants.smtp.notConfigured')}</Alert>
  {/if}

  <FormSection
    title={t('adminTenants.smtp.form.title')}
    intro={t('adminTenants.smtp.intro')}
    {dirty}
    addGuard={(guard) => nav.addGuard(guard)}
    {validate}
    onsubmit={save}
    bind:errors
  >
    <TextField
      id={ids.host}
      label={t('adminTenants.smtp.host.label')}
      hint={t('adminTenants.smtp.host.hint')}
      bind:value={host}
      required
      autocomplete="off"
      spellcheck={false}
      maxlength={253}
      error={errorFor(errors, ids.host)}
    />
    <RadioGroup
      legend={t('adminTenants.smtp.security.label')}
      options={securityOptions}
      bind:value={security}
      required
      error={errorFor(errors, ids.security)}
      onchange={onSecurityChange}
    />
    <TextField
      id={ids.port}
      label={t('adminTenants.smtp.port.label')}
      hint={t('adminTenants.smtp.port.suggested', { port: suggestedPort })}
      bind:value={portText}
      inputmode="numeric"
      autocomplete="off"
      required
      error={errorFor(errors, ids.port)}
    />
    {#if parsePort(portText) !== suggestedPort}
      <p class="tt-smtp__suggest">
        <Button variant="secondary" small onclick={() => (portText = String(suggestedPort))}>
          {t('adminTenants.smtp.port.useSuggested', { port: suggestedPort })}
        </Button>
      </p>
    {/if}
    <TextField
      id={ids.username}
      label={t('adminTenants.smtp.username.label')}
      hint={t('adminTenants.smtp.username.hint')}
      bind:value={username}
      autocomplete="off"
      spellcheck={false}
      maxlength={320}
      error={errorFor(errors, ids.username)}
    />
    <SecretModeField
      id={ids.password}
      legend={stored?.passwordSet === true
        ? t('adminTenants.smtp.password.mode')
        : t('adminTenants.smtp.password.label')}
      secretSet={stored?.passwordSet === true}
      bind:mode={passwordMode}
      bind:value={password}
      newLabel={t('adminTenants.smtp.password.new')}
      keepLabel={t('adminTenants.smtp.password.keep')}
      replaceLabel={t('adminTenants.smtp.password.replace')}
      removeLabel={t('adminTenants.smtp.password.remove')}
      setNotice={t('adminTenants.smtp.password.set')}
      hint={t('adminTenants.smtp.password.encrypted')}
      error={errorFor(errors, ids.password)}
    />
    {#if insecure}
      <Alert severity="warning" live={false}>{t('adminTenants.smtp.warnings.credentialsOverNone')}</Alert>
    {/if}
    <TextField
      id={ids.fromAddress}
      type="email"
      label={t('adminTenants.smtp.fromAddress.label')}
      hint={t('adminTenants.smtp.fromAddress.hint')}
      bind:value={fromAddress}
      required
      autocomplete="off"
      spellcheck={false}
      error={errorFor(errors, ids.fromAddress)}
    />
    <TextField
      id={ids.fromName}
      label={t('adminTenants.smtp.fromName.label')}
      hint={t('adminTenants.smtp.fromName.hint')}
      bind:value={fromName}
      autocomplete="off"
      maxlength={100}
      error={errorFor(errors, ids.fromName)}
    />
  </FormSection>

  <section class="tt-smtp__section" aria-labelledby="{uid}-test-heading">
    <h2 id="{uid}-test-heading">{t('adminTenants.smtp.test.title')}</h2>
    <p class="tt-smtp__intro">{t('adminTenants.smtp.test.intro')}</p>
    <form novalidate onsubmit={sendTest} aria-labelledby="{uid}-test-heading">
      <TextField
        id={ids.to}
        type="email"
        label={t('adminTenants.smtp.test.to.label')}
        hint={t('adminTenants.smtp.test.to.hint')}
        bind:value={to}
        oninput={() => (toTouched = true)}
        required
        autocomplete="off"
        spellcheck={false}
        error={toError}
      />
      <Button
        type="submit"
        loading={testing}
        loadingLabel={t('adminTenants.smtp.test.sending')}
        disabled={stored === null}
      >
        {t('adminTenants.smtp.test.submit')}
      </Button>
    </form>
    {#if testResult !== undefined}
      <Alert
        severity={testResult.success ? 'success' : 'error'}
        title={t(testResult.title.key, testResult.title.params)}
      >
        <p>{t(testResult.stage.key, testResult.stage.params)}</p>
        <p>{t(testResult.duration.key, testResult.duration.params)}</p>
        {#if testResult.error !== undefined}
          <p>{t('adminTenants.smtp.test.serverMessage')}</p>
          <pre class="tt-break tt-smtp__pre">{testResult.error}</pre>
        {/if}
      </Alert>
    {/if}
    {#if testFailure !== ''}
      <Alert severity="error">{testFailure}</Alert>
    {/if}
  </section>

  <section class="tt-smtp__section" aria-labelledby="{uid}-dns-heading">
    <h2 id="{uid}-dns-heading">{t('adminTenants.smtp.dns.title')}</h2>
    <p class="tt-smtp__intro">{t('adminTenants.smtp.dns.intro')}</p>
    {#if stored === null}
      <p>{t('adminTenants.smtp.dns.notConfigured')}</p>
    {:else}
      <form novalidate onsubmit={checkDns} aria-labelledby="{uid}-dns-heading">
        <TextField
          id={ids.selectors}
          label={t('adminTenants.smtp.dns.selectors.label')}
          hint={t('adminTenants.smtp.dns.selectors.hint')}
          bind:value={selectorsText}
          autocomplete="off"
          spellcheck={false}
          error={selectorsFieldError}
        />
        <Button type="submit" loading={checking} loadingLabel={t('adminTenants.smtp.dns.checking')}>
          {t('adminTenants.smtp.dns.submit')}
        </Button>
      </form>
    {/if}
    {#if dnsNotConfigured}
      <Alert severity="info">{t('adminTenants.smtp.dns.notConfigured')}</Alert>
    {/if}
    {#if dnsFailure !== ''}
      <Alert severity="error">{dnsFailure}</Alert>
    {/if}
    {#if dnsCheck !== undefined}
      <div class="tt-smtp__table-wrap">
        <table class="tt-smtp__table">
          <caption class="tt-break">{t('adminTenants.smtp.dns.domain', { domain: dnsCheck.domain })}</caption>
          <thead>
            <tr>
              <th scope="col">{t('adminTenants.smtp.dns.columns.check')}</th>
              <th scope="col">{t('adminTenants.smtp.dns.columns.status')}</th>
              <th scope="col">{t('adminTenants.smtp.dns.columns.record')}</th>
              <th scope="col">{t('adminTenants.smtp.dns.columns.details')}</th>
            </tr>
          </thead>
          <tbody>
            {#each rows as row (row.id)}
              <tr>
                <th scope="row">{t(row.label)}</th>
                <td><StatusBadge variant={dnsVariant(row.status)} label={t(row.statusLabel)} /></td>
                <td>
                  {#if row.record !== undefined}
                    <code class="tt-break">{row.record}</code>
                  {:else}
                    {t('admin.common.none')}
                  {/if}
                </td>
                <td>
                  {#if row.message !== undefined}<p class="tt-break tt-smtp__cell">{row.message}</p>{/if}
                  {#if row.selectors.length > 0}
                    <ul class="tt-smtp__selectors">
                      {#each row.selectors as s, i (i)}
                        <li class="tt-break">{t(s.key, s.params)}</li>
                      {/each}
                    </ul>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
{/if}

<style>
  .tt-smtp__suggest {
    margin: calc(-1 * var(--tt-space-2)) 0 var(--tt-space-4);
  }

  .tt-smtp__section {
    margin-bottom: var(--tt-space-8);
  }

  .tt-smtp__intro {
    margin: 0 0 var(--tt-space-4);
    color: var(--tt-muted);
  }

  .tt-smtp__section form {
    margin-bottom: var(--tt-space-4);
  }

  .tt-smtp__pre {
    margin: var(--tt-space-1) 0 0;
    white-space: pre-wrap;
    font-family: var(--tt-font-mono);
    font-size: var(--tt-font-size-sm);
  }

  .tt-smtp__table-wrap {
    overflow-x: auto;
  }

  .tt-smtp__table {
    width: 100%;
    border-collapse: collapse;
  }

  .tt-smtp__table caption {
    margin-bottom: var(--tt-space-2);
    text-align: left;
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-smtp__table th,
  .tt-smtp__table td {
    padding: var(--tt-space-2);
    border-bottom: var(--tt-border-width) solid var(--tt-border);
    text-align: left;
    vertical-align: top;
  }

  .tt-smtp__cell {
    margin: 0;
  }

  .tt-smtp__selectors {
    margin: 0;
    padding-left: var(--tt-space-5);
  }
</style>
