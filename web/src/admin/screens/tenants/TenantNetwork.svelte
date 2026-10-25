<script lang="ts">
  // Network rules of a tenant (CLAUDE.md section 6.2): a user is internal when their IP address
  // belongs to an internal range and their email address to an internal domain.
  // - two line lists (GET/PUT /admin/tenants/{id}/network), checked live with an error per line
  //   and a suggested correction when one can be inferred;
  // - the save is refused while a list has invalid lines or too many entries;
  // - warnings (not blocking): an empty list makes nobody internal, a catch-all range makes every
  //   client of an internal domain internal;
  // - the lists then show the values saved by the server, which normalises them again.
  // The tenant sub-navigation is rendered by App.svelte.
  import { describeError } from '../../../shared/api/problem';
  import { Alert, HelpIcon, Spinner } from '../../../shared/components';
  import { i18n, t } from '../../../shared/i18n/i18n.svelte';
  import { adminApi } from '../../api';
  import FormSection from '../../components/FormSection.svelte';
  import LineListEditor from '../../components/LineListEditor.svelte';
  import { errorFor, summaryFromFields, type SubmitOutcome, type SummaryError } from '../../components/form';
  import { MAX_INTERNAL_CIDRS, parseCidr, parseCidrList } from '../../forms/cidr';
  import { MAX_INTERNAL_DOMAINS, parseDomain, parseDomainList } from '../../forms/domain';
  import { joinLines } from '../../forms/lines';
  import type { AdminScreenProps } from '../types';
  import {
    cidrLineMessage,
    domainLineMessage,
    networkBody,
    networkWarnings,
    sameRules,
    validateNetwork,
    wasNormalized,
    type NetworkRules,
  } from './network';

  const { params, nav }: AdminScreenProps = $props();

  const uid = $props.id();
  const ids = { cidrs: `${uid}-cidrs`, domains: `${uid}-domains` };

  let loading = $state(true);
  let loadError = $state('');
  let saved = $state.raw<NetworkRules | undefined>(undefined);
  let cidrText = $state('');
  let domainText = $state('');
  let errors = $state<SummaryError[]>([]);
  let normalizedNotice = $state(false);

  // Parsed here as well, so that the warnings and the body never wait for the editors.
  const cidrs = $derived(parseCidrList(cidrText));
  const domains = $derived(parseDomainList(domainText));
  const warnings = $derived(networkWarnings(cidrs, domains));
  const fields = $derived({
    internalCidrs: { id: ids.cidrs, label: t('adminTenants.network.cidrs.label') },
    internalDomains: { id: ids.domains, label: t('adminTenants.network.domains.label') },
  });
  // An invalid line or too many entries also counts as a change: the save then runs the
  // validation (error summary) instead of answering that there is nothing to save.
  const dirty = $derived(
    saved !== undefined &&
      (!sameRules(saved, networkBody(cidrs, domains)) ||
        cidrs.errors.length > 0 ||
        domains.errors.length > 0 ||
        cidrs.tooMany ||
        domains.tooMany),
  );
  const tenantId = $derived(params['id'] ?? '');

  $effect(() => {
    if (dirty) {
      normalizedNotice = false;
    }
  });

  function show(rules: NetworkRules): void {
    saved = rules;
    cidrText = joinLines(rules.internalCidrs);
    domainText = joinLines(rules.internalDomains);
  }

  async function load(id: string): Promise<void> {
    loading = true;
    loadError = '';
    try {
      const res = await adminApi.get('/admin/tenants/{tenantId}/network', { path: { tenantId: id } });
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
    const typedCidrs = cidrText;
    const typedDomains = domainText;
    try {
      const res = await adminApi.put('/admin/tenants/{tenantId}/network', {
        path: { tenantId },
        body: networkBody(cidrs, domains),
      });
      const normalized = wasNormalized(typedCidrs, typedDomains, res.data);
      show(res.data);
      normalizedNotice = normalized;
      return { ok: true, message: t('adminTenants.network.saved') };
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
  <h1 tabindex="-1">{t('adminTenants.network.title')}</h1>
  <HelpIcon topic="tenant-network" title={t('adminTenants.network.title')} {nav} />
</div>

{#if loading}
  <p><Spinner showLabel /></p>
{:else if loadError !== ''}
  <Alert severity="error">{loadError}</Alert>
{:else}
  <FormSection
    title={t('adminTenants.network.form.title')}
    intro={t('adminTenants.network.intro')}
    {dirty}
    addGuard={(guard) => nav.addGuard(guard)}
    validate={() => validateNetwork(cidrs, domains, fields, t)}
    onsubmit={save}
    bind:errors
  >
    <LineListEditor
      id={ids.cidrs}
      label={t('adminTenants.network.cidrs.label')}
      hint={t('adminTenants.network.cidrs.hint')}
      bind:value={cidrText}
      parse={parseCidr}
      max={MAX_INTERNAL_CIDRS}
      message={(e) => {
        const m = cidrLineMessage(e);
        return t(m.key, m.params);
      }}
      error={errorFor(errors, ids.cidrs)}
    />
    <LineListEditor
      id={ids.domains}
      label={t('adminTenants.network.domains.label')}
      hint={t('adminTenants.network.domains.hint')}
      bind:value={domainText}
      parse={parseDomain}
      max={MAX_INTERNAL_DOMAINS}
      message={(e) => {
        const m = domainLineMessage(e);
        return t(m.key, m.params);
      }}
      error={errorFor(errors, ids.domains)}
    />
    {#if warnings.length > 0}
      <Alert severity="warning" live={false}>
        <ul class="tt-network__warnings">
          {#each warnings as w (w.key + (w.params?.['range'] ?? ''))}
            <li>{t(w.key, w.params)}</li>
          {/each}
        </ul>
      </Alert>
    {/if}
    {#if normalizedNotice}
      <Alert severity="info">{t('adminTenants.network.normalized')}</Alert>
    {/if}
  </FormSection>
{/if}

<style>
  .tt-network__warnings {
    margin: 0;
    padding-left: var(--tt-space-5);
  }
</style>
