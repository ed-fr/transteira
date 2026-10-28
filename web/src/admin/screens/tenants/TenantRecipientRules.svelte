<script lang="ts">
  // Recipient domain rules of a tenant (CLAUDE.md section 8.4, version 1.1): two line lists
  // (GET/PUT /admin/tenants/{id}/recipient-rules), checked live with an error per line. Subdomains
  // are included, the deny list wins, a non-empty allow list restricts recipients to it. Same
  // behaviour as the network screen: no save while a list has invalid lines, non-blocking
  // warnings, lists shown again with the values normalised by the server.
  // The tenant sub-navigation is rendered by App.svelte.
  import { describeError } from '../../../shared/api/problem';
  import { Alert, HelpIcon, Spinner } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import FormSection from '../../components/FormSection.svelte';
  import LineListEditor from '../../components/LineListEditor.svelte';
  import { errorFor, summaryFromFields, type SubmitOutcome, type SummaryError } from '../../components/form';
  import { parseDomain } from '../../forms/domain';
  import { joinLines } from '../../forms/lines';
  import type { AdminScreenProps } from '../types';
  import { domainLineMessage } from './network';
  import {
    MAX_RECIPIENT_DOMAINS,
    parseRuleList,
    recipientRulesBody,
    recipientRulesNormalized,
    recipientWarnings,
    sameRecipientRules,
    validateRecipientRules,
    type RecipientRules,
  } from './recipientRules';

  const { params, nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids = { allowed: `${uid}-allowed`, denied: `${uid}-denied` };

  let loading = $state(true);
  let loadError = $state('');
  let saved = $state.raw<RecipientRules | undefined>(undefined);
  let allowedText = $state('');
  let deniedText = $state('');
  let errors = $state<SummaryError[]>([]);
  let normalizedNotice = $state(false);

  const allowed = $derived(parseRuleList(allowedText));
  const denied = $derived(parseRuleList(deniedText));
  const warnings = $derived(recipientWarnings(allowed, denied));
  const fields = $derived({
    allowedDomains: { id: ids.allowed, label: t('adminTenants.recipientRules.allowed.label') },
    deniedDomains: { id: ids.denied, label: t('adminTenants.recipientRules.denied.label') },
  });
  const dirty = $derived(
    saved !== undefined &&
      (!sameRecipientRules(saved, recipientRulesBody(allowed, denied)) ||
        allowed.errors.length > 0 ||
        denied.errors.length > 0 ||
        allowed.tooMany ||
        denied.tooMany),
  );
  const tenantId = $derived(params['id'] ?? '');

  $effect(() => {
    if (dirty) {
      normalizedNotice = false;
    }
  });

  function show(rules: RecipientRules): void {
    saved = rules;
    allowedText = joinLines(rules.allowedDomains);
    deniedText = joinLines(rules.deniedDomains);
  }

  async function load(id: string): Promise<void> {
    loading = true;
    loadError = '';
    try {
      const res = await adminApi.get('/admin/tenants/{tenantId}/recipient-rules', { path: { tenantId: id } });
      show(res.data);
    } catch (err) {
      loadError = describeError(i18n, err).message;
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    void load(tenantId);
  });

  async function save(): Promise<SubmitOutcome> {
    const typedAllowed = allowedText;
    const typedDenied = deniedText;
    try {
      const res = await adminApi.put('/admin/tenants/{tenantId}/recipient-rules', {
        path: { tenantId },
        body: recipientRulesBody(allowed, denied),
      });
      const normalized = recipientRulesNormalized(typedAllowed, typedDenied, res.data);
      show(res.data);
      normalizedNotice = normalized;
      return { ok: true, message: t('adminTenants.recipientRules.saved') };
    } catch (err) {
      const view = describeError(i18n, err);
      const mapped = summaryFromFields(view.fields, fields);
      const message = mapped.errors.length === 0 || mapped.unmatched.length > 0 ? view.message : undefined;
      return message === undefined
        ? { ok: false, errors: mapped.errors }
        : { ok: false, errors: mapped.errors, message };
    }
  }
</script>

<div class="tt-title-row">
  <h1 tabindex="-1">{t('adminTenants.recipientRules.title')}</h1>
  <HelpIcon topic="tenant-recipient-rules" title={t('adminTenants.recipientRules.title')} {nav} />
</div>

{#if loading}
  <p><Spinner showLabel /></p>
{:else if loadError !== ''}
  <Alert severity="error">{loadError}</Alert>
{:else}
  <FormSection
    title={t('adminTenants.recipientRules.form.title')}
    intro={t('adminTenants.recipientRules.intro')}
    {dirty}
    addGuard={(guard) => nav.addGuard(guard)}
    validate={() => validateRecipientRules(allowed, denied, fields, t)}
    onsubmit={save}
    bind:errors
  >
    <LineListEditor
      id={ids.allowed}
      label={t('adminTenants.recipientRules.allowed.label')}
      hint={t('adminTenants.recipientRules.allowed.hint')}
      bind:value={allowedText}
      parse={parseDomain}
      max={MAX_RECIPIENT_DOMAINS}
      message={(e) => {
        const m = domainLineMessage(e);
        return t(m.key, m.params);
      }}
      error={errorFor(errors, ids.allowed)}
    />
    <LineListEditor
      id={ids.denied}
      label={t('adminTenants.recipientRules.denied.label')}
      hint={t('adminTenants.recipientRules.denied.hint')}
      bind:value={deniedText}
      parse={parseDomain}
      max={MAX_RECIPIENT_DOMAINS}
      message={(e) => {
        const m = domainLineMessage(e);
        return t(m.key, m.params);
      }}
      error={errorFor(errors, ids.denied)}
    />
    {#if warnings.length > 0}
      <Alert severity="warning" live={false}>
        <ul class="tt-recipient-rules__warnings">
          {#each warnings as w (w.key + (w.params?.['domain'] ?? ''))}
            <li>{t(w.key, w.params)}</li>
          {/each}
        </ul>
      </Alert>
    {/if}
    {#if normalizedNotice}
      <Alert severity="info">{t('adminTenants.recipientRules.normalized')}</Alert>
    {/if}
  </FormSection>
{/if}

<style>
  .tt-recipient-rules__warnings {
    margin: 0;
    padding-left: var(--tt-space-5);
  }
</style>
