<script lang="ts">
  // Files column of the deposit form (CLAUDE.md section 13.2, left pane on --tt-surface-muted): the
  // title of the step, a subtitle (size limit, encryption, antivirus when it applies), the large
  // drop zone with "Choose files" and "Choose a folder", the selected files as cards (type badge,
  // name, size, remove button) and the volume gauge against the limit of the transfer (the
  // encrypted sizes with end-to-end encryption). Adding and removing files is announced (the
  // number of files and the total size); after a removal the focus goes to the file input.
  // Links never sit on this muted pane in the tenant colour (none is rendered here).
  import { tick } from 'svelte';
  import { announce, FileDrop, FileList, VolumeGauge } from '../../../shared/components';
  import type { AcceptedFile } from '../../../shared/components/folders';
  import { formatBytes, t } from '../../../shared/i18n/i18n.svelte';
  import type { DepositFile, DepositFlow } from '../flow.svelte';
  import { MAX_FILES, type Message } from '../form';
  import { FIELD_IDS, subtitleParts } from '../view';

  interface Props {
    flow: DepositFlow;
    /** Error of the files field (none, too many, too large, invalid names). */
    error?: string | undefined;
    /** Errors of individual file names, by file index. */
    nameIssues: ReadonlyMap<number, Message>;
  }

  let { flow, error, nameIssues }: Props = $props();

  let input: HTMLInputElement | undefined = $state();

  const limit = $derived(flow.limits.maxTransferBytes);
  const subtitle = $derived(
    subtitleParts({ max: formatBytes(limit), e2e: flow.e2eEffective, antivirus: flow.antivirusMentioned }),
  );

  /** Text of the volume of the selection, announced after a change. */
  function volumeText(): string {
    const summary = t('components.volumeGauge.summary', {
      count: flow.form.files.length,
      size: formatBytes(flow.totalBytes),
    });
    return flow.totalBytes > limit
      ? `${summary} ${t('components.volumeGauge.over', { limit: formatBytes(limit) })}`
      : summary;
  }

  function added(files: readonly DepositFile[]): void {
    flow.addFiles(files);
    announce(volumeText());
  }

  function picked(files: readonly AcceptedFile<DepositFile>[]): void {
    flow.addPicked(files);
    announce(volumeText());
  }

  async function removed(index: number, name: string): Promise<void> {
    flow.removeFile(index);
    announce(`${t('deposit.form.files.removed', { name })} ${volumeText()}`);
    await tick();
    input?.focus();
  }
</script>

<div class="tt-deposit-heading">
  <h1 tabindex="-1">{t('deposit.form.title')}</h1>
  <p class="tt-deposit-subtitle">
    {#each subtitle as part, i (part.key)}
      {#if i > 0}<span class="tt-deposit-subtitle__dot" aria-hidden="true">·</span><span
          class="visually-hidden">,</span
        >{/if}<span>{t(part.key, part.params)}</span>
    {/each}
  </p>
</div>

<FileDrop
  id={FIELD_IDS.files}
  variant="hero"
  label={t('deposit.form.files.label')}
  hint={t('deposit.form.files.hint', { max: formatBytes(limit), count: MAX_FILES })}
  required
  {error}
  onfiles={added}
  folders={flow.foldersEnabled}
  onpicked={picked}
  room={flow.fileRoom}
  bind:element={input}
/>

<FileList
  variant="cards"
  files={flow.form.files}
  onremove={(index, file) => void removed(index, file.name)}
  disabled={flow.busy}
>
  {#snippet details(_file, index)}
    {@const issue = nameIssues.get(index)}
    {#if issue}
      <p class="tt-text-danger tt-text-sm tt-mb-0">{t(issue.key, issue.params)}</p>
    {/if}
  {/snippet}
</FileList>

{#if flow.form.files.length > 0}
  <VolumeGauge used={flow.totalBytes} count={flow.form.files.length} {limit} />
{/if}

<style>
  .tt-deposit-heading h1 {
    margin-bottom: var(--tt-space-1);
  }

  .tt-deposit-subtitle {
    display: flex;
    flex-wrap: wrap;
    gap: 0 var(--tt-space-2);
    margin: 0;
    color: var(--tt-muted);
  }

  .tt-deposit-subtitle__dot {
    font-weight: var(--tt-font-weight-bold);
  }
</style>
