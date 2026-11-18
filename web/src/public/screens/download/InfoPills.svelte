<script lang="ts">
  // Information pills of the download page (CLAUDE.md section 13.2), a list named "About this
  // transfer": the relative expiry ("Expires in 6 days") in a <time> element whose datetime holds
  // the exact date, also shown as tooltip and read by screen readers; the confidentiality level
  // (its name visible, "Confidentiality:" for screen readers); the downloads left; the total size.
  // Each pill is shown only when its value is known.
  //
  // Props:
  //   expiresAt           expiry of the transfer (ISO 8601)
  //   now                 clock of the relative expiry (epoch milliseconds: the last load, moved on
  //                       by the page while it stays open)
  //   levelLabel          name of the confidentiality level
  //   downloadsRemaining  downloads left before the maximum is reached
  //   totalBytes          total size of the files
  import { Pill } from '../../../shared/components';
  import { formatBytes, formatDate, formatRelative, t } from '../../../shared/i18n/i18n.svelte';
  import { expiryView } from '../outcomes';

  interface Props {
    /** Expiry of the transfer (ISO 8601). */
    expiresAt: string;
    /** Clock of the relative expiry (epoch milliseconds). */
    now: number;
    /** Name of the confidentiality level. */
    levelLabel?: string | undefined;
    /** Downloads left before the maximum is reached. */
    downloadsRemaining?: number | undefined;
    /** Total size of the files. */
    totalBytes?: number | undefined;
  }

  let { expiresAt, now, levelLabel, downloadsRemaining, totalBytes }: Props = $props();

  const expiry = $derived(expiryView(expiresAt, now));
  const absolute = $derived(
    expiry === undefined ? '' : formatDate(expiry.date, { dateStyle: 'long', timeStyle: 'short' }),
  );
</script>

<ul class="tt-dlpills" aria-label={t('download.pills.label')}>
  {#if expiry !== undefined}
    <Pill tag="li" icon="clock">
      <time datetime={expiry.datetime} title={absolute}
        >{t('download.pills.expires', { relative: formatRelative(expiry.relative, now) })}</time
      ><span class="visually-hidden"> {t('download.pills.until', { date: absolute })}</span>
    </Pill>
  {/if}
  {#if levelLabel !== undefined}
    <Pill tag="li" icon="shield">
      <span class="visually-hidden">{t('download.pills.level')} </span><span>{levelLabel}</span>
    </Pill>
  {/if}
  {#if downloadsRemaining !== undefined}
    <Pill tag="li" icon="download">
      {t('download.pills.downloadsLeft', { count: downloadsRemaining })}
    </Pill>
  {/if}
  {#if totalBytes !== undefined}
    <Pill tag="li" icon="file">
      {t('download.pills.total', { size: formatBytes(totalBytes) })}
    </Pill>
  {/if}
</ul>

<style>
  .tt-dlpills {
    display: flex;
    flex-wrap: wrap;
    gap: var(--tt-space-2);
    margin: 0;
    padding: 0;
    list-style: none;
  }
</style>
