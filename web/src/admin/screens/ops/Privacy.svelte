<script lang="ts">
  // Data subject rights of a tenant (CLAUDE.md section 20): search the data linked to an address
  // (POST .../data-subjects/search), then erase it (POST .../data-subjects/erase) after a
  // confirmation where the exact address must be typed, and show the erasure report with a link
  // to the audit log filtered on the erasures. The address is only sent in POST bodies: it never
  // goes into the URL, the browser storage or an announcement, and the address and the results
  // are cleared when leaving the screen (T-168). Only this tenant is searched and erased. The
  // tenant sub-navigation is rendered by App.svelte.
  import { onDestroy, tick } from 'svelte';
  import { describeError } from '../../../shared/api/problem';
  import { Alert, Button, TextField } from '../../../shared/components';
  import { formatNumber, i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { EMAIL_MAX_LENGTH } from '../../../shared/validation/email';
  import { adminApi } from '../../api';
  import ConfirmDialog from '../../components/ConfirmDialog.svelte';
  import FormSection from '../../components/FormSection.svelte';
  import { errorFor, type SubmitOutcome, type SummaryError } from '../../components/form';
  import type { AdminScreenProps } from '../types';
  import {
    ERASED_KEYS,
    KEPT_KEYS,
    auditLinkPath,
    confirmTextFor,
    eraseFailure,
    hasData,
    reportRows,
    requestBody,
    searchFailure,
    summaryRows,
    validateAddress,
    type DataSubjectEraseReport,
    type DataSubjectSummary,
  } from './privacy';

  let { params, nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const emailId = `${uid}-email`;
  const tenantId = $derived(params['id'] ?? '');
  const format = (n: number): string => formatNumber(n);

  let email = $state('');
  let searched = $state('');
  let summary = $state.raw<DataSubjectSummary | null>(null);
  let report = $state.raw<DataSubjectEraseReport | null>(null);
  let errors = $state<SummaryError[]>([]);
  let confirmOpen = $state(false);
  let emailInput = $state<HTMLInputElement | undefined>(undefined);
  let reportHeading = $state<HTMLHeadingElement | undefined>(undefined);

  const emailRef = $derived({ id: emailId, label: t('opsPrivacy.search.email') });

  /** Forgets the address and every result (new search, leaving the screen). */
  function clear(): void {
    email = '';
    searched = '';
    summary = null;
    report = null;
    errors = [];
    confirmOpen = false;
  }

  onDestroy(clear);

  function validate(): SummaryError[] {
    return validateAddress(email, emailRef, t);
  }

  async function search(): Promise<SubmitOutcome> {
    const body = requestBody(email);
    try {
      const res = await adminApi.post('/admin/tenants/{tenantId}/data-subjects/search', {
        path: { tenantId },
        body,
      });
      searched = body.email;
      summary = res.data;
      report = null;
      return { ok: true, message: t('opsPrivacy.search.done') };
    } catch (err) {
      return searchFailure(describeError(i18n, err), emailRef, t);
    }
  }

  async function erase(): Promise<string | void> {
    try {
      const res = await adminApi.post('/admin/tenants/{tenantId}/data-subjects/erase', {
        path: { tenantId },
        body: requestBody(searched),
      });
      report = res.data;
      summary = null;
      email = '';
      await tick();
      reportHeading?.focus();
    } catch (err) {
      return eraseFailure(describeError(i18n, err), t);
    }
  }

  async function newSearch(): Promise<void> {
    clear();
    await tick();
    emailInput?.focus();
  }
</script>

<h1 tabindex="-1">{t('adminOps.privacy.title')}</h1>
<p>{t('adminOps.privacy.intro')}</p>
<Alert severity="info" live={false}>
  <p>{t('opsPrivacy.scope')}</p>
</Alert>

{#if report === null}
  <FormSection
    title={t('opsPrivacy.search.title')}
    {validate}
    onsubmit={search}
    bind:errors
    saveLabel={t('opsPrivacy.search.submit')}
    savingLabel={t('opsPrivacy.search.submitting')}
  >
    <TextField
      id={emailId}
      type="email"
      label={t('opsPrivacy.search.email')}
      hint={t('opsPrivacy.search.hint')}
      bind:value={email}
      bind:element={emailInput}
      required
      autocomplete="off"
      spellcheck={false}
      maxlength={EMAIL_MAX_LENGTH}
      error={errorFor(errors, emailId)}
    />
  </FormSection>
{/if}

{#if summary !== null}
  <section class="tt-privacy__block" aria-labelledby="{uid}-summary">
    <h2 id="{uid}-summary">{t('opsPrivacy.summary.title')}</h2>
    <p>
      {t('opsPrivacy.summary.for')} <strong class="tt-break">{searched}</strong>
    </p>
    {#if !hasData(summary)}
      <Alert severity="info" live={false}>
        <p>{t('opsPrivacy.summary.nothing')}</p>
      </Alert>
    {/if}
    <dl class="tt-privacy__list">
      {#each summaryRows(summary, t, format) as row (row.id)}
        <div class="tt-privacy__row">
          <dt>{row.term}</dt>
          <dd>{row.value}</dd>
        </div>
      {/each}
    </dl>
    <p class="tt-privacy__note">{t('opsPrivacy.summary.securityNote')}</p>
    <Button variant="danger" onclick={() => (confirmOpen = true)}>{t('opsPrivacy.erase.open')}</Button>
  </section>

  <ConfirmDialog
    bind:open={confirmOpen}
    title={t('opsPrivacy.erase.title')}
    danger
    confirmLabel={t('opsPrivacy.erase.confirm')}
    busyLabel={t('opsPrivacy.erase.busy')}
    confirmText={confirmTextFor(searched)}
    onconfirm={erase}
  >
    <p>{t('opsPrivacy.erase.scope')}</p>
    <p>{t('opsPrivacy.erase.erasedIntro')}</p>
    <ul>
      {#each ERASED_KEYS as key (key)}
        <li>{t(key)}</li>
      {/each}
    </ul>
    <p>{t('opsPrivacy.erase.keptIntro')}</p>
    <ul>
      {#each KEPT_KEYS as key (key)}
        <li>{t(key)}</li>
      {/each}
    </ul>
    <p>{t('opsPrivacy.erase.irreversible')}</p>
  </ConfirmDialog>
{/if}

{#if report !== null}
  <section class="tt-privacy__block" aria-labelledby="{uid}-report">
    <h2 id="{uid}-report" tabindex="-1" bind:this={reportHeading}>{t('opsPrivacy.report.title')}</h2>
    <Alert severity="success" live={false}>
      <p>{t('opsPrivacy.report.done')}</p>
    </Alert>
    <dl class="tt-privacy__list">
      {#each reportRows(report, t, format) as row (row.id)}
        <div class="tt-privacy__row">
          <dt>{row.term}</dt>
          <dd>{row.value}</dd>
        </div>
      {/each}
    </dl>
    <p>{t('opsPrivacy.report.auditHint')}</p>
    <p>
      <a href={nav.href(auditLinkPath(tenantId))} use:nav.link>{t('opsPrivacy.report.auditLink')}</a>
    </p>
    <Button variant="secondary" onclick={() => void newSearch()}>{t('opsPrivacy.report.newSearch')}</Button>
  </section>
{/if}

<style>
  .tt-privacy__block {
    margin-top: var(--tt-space-6);
  }

  .tt-privacy__list {
    margin: var(--tt-space-4) 0;
    padding: 0;
  }

  .tt-privacy__row {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    gap: var(--tt-space-2);
    padding: var(--tt-space-2) 0;
    border-bottom: var(--tt-border-width) solid var(--tt-border);
  }

  .tt-privacy__row dt {
    font-weight: var(--tt-font-weight-bold);
  }

  .tt-privacy__row dd {
    margin: 0;
    font-variant-numeric: tabular-nums;
  }

  .tt-privacy__note {
    color: var(--tt-muted);
    font-size: var(--tt-font-size-sm);
  }
</style>
