# Antivirus (ClamAV)

Every deposited file is scanned by ClamAV before anyone can download it
(specification section 11). TransTeira talks to `clamd` over its network
protocol (`INSTREAM`); ClamAV runs in its own container on the internal Docker
network, never on the network shared with the reverse proxy.

- Variables: `TT_CLAMAV_ADDR`, `TT_CLAMAV_MAX_SCAN_BYTES`, `TT_CLAMAV_TIMEOUT`,
  `TT_SCAN_WORKERS` (see `.env.example`).
- Packages: `internal/antivirus` (clamd client), `internal/scan` (worker).
- Threat model: T-41 to T-46, decision P10.

## What happens after a deposit

1. The sender finalizes the transfer; it becomes `scanning`.
2. A scan worker decrypts each stored file on the fly and streams it to clamd.
   The plaintext never touches the disk, and what is scanned is exactly what
   will be served.
3. Each file gets a final status:

| Status | Meaning | Downloadable |
|---|---|---|
| `clean` | No threat found. | yes |
| `infected` | Threat found: the file key is destroyed and the file erased; the row stays so that the sender knows which file it was. | no |
| `not_scanned_too_large` | Larger than `TT_CLAMAV_MAX_SCAN_BYTES`, refused by clamd's stream limit, or only partly analysed because of clamd's archive limits (`Heuristics.Limits.Exceeded`). Accepted, and flagged to the sender and recipients (section 11). | yes |
| `not_scanned_encrypted` | Encrypted (password-protected) archive that clamd cannot analyse (`Heuristics.Encrypted`). Accepted and flagged the same way. | yes |
| `scan_error` | The file could not be analysed after 3 attempts: unexpected clamd reply, unreadable file, clamd timing out on it, or clamd dropping the connection on it while still answering pings. Withheld for safety. | no |

4. When every file is done:
   - at least one deliverable file: the transfer becomes `available`, a
     download link is created, the chosen validity (1, 7 or 30 days) starts
     at that moment, each recipient receives their own mail (link,
     inline QR code, SHA-256 fingerprints) and the sender a confirmation;
   - no deliverable file: the transfer becomes `rejected` and no recipient is
     notified.

   The sender is told about infected or withheld files (`file_problems` mail)
   and about files that could not be analysed because they are too large, too
   complex or encrypted (`file_not_scanned` mail).

## When clamd is unavailable (fail-closed)

If clamd cannot be reached, nothing is made available (decision P10). The
transfer stays `scanning`, the worker retries with an increasing delay (30 s,
doubling up to 10 min) and logs **one** warning per incident, then one
message when clamd answers again. Transfers still `scanning` when TransTeira
stops are resumed at the next start. `/healthz` reports `clamav: unavailable`
meanwhile, so your monitoring (for example Uptime Kuma) can alert you.

The validity of a transfer (1, 7 or 30 days) starts when it becomes
available, so an outage never shortens it. A transfer still `scanning`
30 days after its finalization is abandoned by the cleanup task: its keys
and files are erased, it becomes `expired`, and a warning naming the tenant
and transfer identifiers is logged. Its sender gets no mail: watch the
health check and the logs so that an outage never lasts that long.

## Size limits

ClamAV limits how much data it accepts and scans. Align its configuration
(`clamd.conf`, or the environment of the official image) with
`TT_CLAMAV_MAX_SCAN_BYTES` (default 2 GiB, at most 4 GiB minus one byte, the
protocol limit):

| clamd setting | Recommended value |
|---|---|
| `StreamMaxLength` | equal to `TT_CLAMAV_MAX_SCAN_BYTES` |
| `MaxScanSize` | equal to `TT_CLAMAV_MAX_SCAN_BYTES` |
| `MaxFileSize` | equal to `TT_CLAMAV_MAX_SCAN_BYTES` |
| `MaxRecursion`, `MaxFiles` | keep the defaults (protection against archive bombs, T-43) |
| `AlertExceedsMax` | `yes` (mandatory) |
| `AlertEncryptedArchive` | `yes` (mandatory) |
| `AlertEncryptedDoc` | `yes` (mandatory: password-protected Office and PDF documents) |
| `HeuristicScanPrecedence` | `no` (the default: a heuristic never masks a real signature) |
| `MaxScanTime` | below `TT_CLAMAV_TIMEOUT` (for example 8 min), so a slow file is flagged rather than retried |

**`AlertExceedsMax`, `AlertEncryptedArchive` and `AlertEncryptedDoc` are mandatory.** Without
them, clamd silently skips the content it does not analyse (entries past
`MaxFiles` or `MaxRecursion`, inner files above `MaxFileSize`, encrypted
archives and documents) and still answers "OK", so a crafted archive would be recorded
`clean`. With them, clamd reports these cases and TransTeira flags the file
as not (fully) scanned instead.

Files above the limit are not sent to clamd at all. If clamd's own limit is
lower, clamd answers "size limit exceeded" and the file is classified
`not_scanned_too_large` as well. Give the ClamAV container enough memory
(about 2 to 3 GiB with the official signatures) and CPU limits.

Keep `TT_SCAN_WORKERS` at or below clamd's `MaxThreads` (default 10):
scans queued inside clamd may otherwise time out and count as failed
attempts.

`TT_CLAMAV_TIMEOUT` (default 10 min) caps the whole scan of one file,
including the time clamd spends after the last byte; a write that stalls for
more than a minute is cut earlier. A file that times out, or that makes clamd
drop the connection while clamd still answers pings, counts as a failed
attempt: after 3 attempts it is withheld (`scan_error`). This includes a file
that crashes clamd outright (out-of-memory kill, parser crash): every lost
connection counts against the file being scanned, and the outage warning
names the tenant, transfer and file involved. A genuine clamd restart during
a scan therefore costs that file one attempt. When clamd answers "size limit
exceeded" for a file below `TT_CLAMAV_MAX_SCAN_BYTES`, TransTeira logs one
warning: align `StreamMaxLength`.

## Isolation of the ClamAV container

A crafted file that exploits a flaw in ClamAV's parsers could run code in the
ClamAV container. Run it on a network shared only with the application (not
with PostgreSQL), as a non-root user, with a read-only root file system apart
from its signature volume, and with CPU and memory limits.

## Lost notifications

The mails are queued just after the transfer becomes available. If
TransTeira stops in between, the recipients are not notified; the sender sees
the transfer as available, and an administrator can resend the notification
(administration step).

## Signatures

Keep `freshclam` running in the ClamAV container (the official image does it
by default) so that signatures stay current (T-46). A container that cannot
update its signatures keeps scanning with the old ones; monitor its logs.

## Testing with a real ClamAV

`make check` uses a simulated clamd that speaks the real protocol. To test
against a real ClamAV, start one and run the live test:

```sh
docker run -d --name clamav-test -p 127.0.0.1:3310:3310 clamav/clamav:stable
# wait until clamd has loaded its signatures (one to two minutes), then:
TT_TEST_CLAMAV_ADDR=127.0.0.1:3310 make test-clamav
```

The test sends the EICAR test string and a clean file, and checks the
verdicts.
