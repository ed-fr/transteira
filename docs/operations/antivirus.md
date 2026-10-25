# Antivirus (ClamAV)

Every deposited file is scanned by ClamAV before anyone can download it
(specification section 11). TransTeira talks to `clamd` over its network
protocol (`INSTREAM`); ClamAV runs in its own container on the internal Docker
network, never on the network shared with the reverse proxy.

- Variables: `TT_CLAMAV_ADDR`, `TT_CLAMAV_MAX_SCAN_BYTES`, `TT_CLAMAV_TIMEOUT`,
  `TT_SCAN_WORKERS` (see `.env.example`).
- Packages: `internal/antivirus` (clamd client), `internal/scan` (worker).
- Deployment: services `clamav`, `clamav-update` and `clamav-init` of
  [`deploy/docker-compose.yml`](../../deploy/docker-compose.yml), configured
  by [`deploy/clamav/clamd.conf`](../../deploy/clamav/clamd.conf) and
  [`deploy/clamav/freshclam.conf`](../../deploy/clamav/freshclam.conf).
- Threat model: T-41 to T-46, decision P10.

## What happens after a deposit

1. The sender finalizes the transfer; it becomes `scanning`.
2. A scan worker decrypts each stored file on the fly and streams it to clamd.
   TransTeira never writes the plaintext to disk, and what is scanned is
   exactly what will be served. clamd itself spools each stream before
   scanning it: in the provided deployment, that spool is in memory (see
   [The clamd spool](#the-clamd-spool)).
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

TransTeira also alerts the administrators itself when the outage lasts
(antivirus alert). The outage is detected by the antivirus worker while it
analyses deposits: when no deposit is waiting, only `/healthz` shows that
clamd is down.

- an outage shorter than **5 minutes** (a clamd restart, a signature
  reload) alerts nobody: it is only logged (`antivirus outage ended before
  the alert`). Before raising the alert, TransTeira pings clamd once more
  and counts the transfers waiting: if clamd answers, the alert is
  postponed by another 5 minutes, the worker confirming the recovery at its
  next retry; after 3 postponements while the worker still fails (clamd
  answering PING but not the analyses), it is raised anyway. If no transfer
  waits any more, the outage is closed without alert (the next failure
  starts a new one);
- beyond, the alert is **raised**: a warning in the application log, the
  audit event `antivirus.alert_raised` (system actor `antivirus`, details
  `outageSeconds`, `waitingTransfers` and `tenants`) and, if the
  [system SMTP server](admin.md#system-smtp-server) is configured, the
  `antivirus_alert` mail to every super admin that can sign in and to the
  alert address of the system settings (counts only: no entity, file or
  address). The delegated admins of each entity with transfers waiting
  (else the super admins) also receive the entity's `antivirus-unavailable`
  template, customizable by the entity, through the SMTP settings of the
  entity;
- it is sent **once per outage**, and the alert mails are **at least one
  hour apart** whatever the number of outages: an outage within the hour of
  the last mail is logged and audited at once, but mailed only once the
  hour has passed, if it still lasts and transfers still wait (log line
  `antivirus alert not mailed yet: an alert mail was sent less than an hour
  ago`; the mail slot is tried again every 5 minutes). The time of the last
  mail is stored in the database, so a restart keeps the interval;
- the entity mail says whether the super admins were alerted too, or, when
  the system SMTP server is not configured, asks to contact the operator of
  the instance;
- when clamd answers again, the alert **clears**: audit event
  `antivirus.alert_cleared` (details `outageSeconds`), no mail. It also
  clears when no transfer waits any more and clamd answers a PING (checked
  every 5 minutes while the alert is raised).

The outage itself is followed in memory: after a restart, the grace period
starts again from the first failure seen by the new process when it resumes
the waiting transfers (a raised alert of the previous process then has no
matching `antivirus.alert_cleared`).

The validity of a transfer (1, 7 or 30 days) starts when it becomes
available, so an outage never shortens it. A transfer still `scanning`
30 days after its finalization is abandoned by the cleanup task: its keys
and files are erased, it becomes `expired`, and a warning naming the tenant
and transfer identifiers is logged. Its sender gets no mail: watch the
health check and the logs so that an outage never lasts that long.

## Size limits

ClamAV limits how much data it accepts and scans. Align its configuration
with `TT_CLAMAV_MAX_SCAN_BYTES` (default 2 GiB, at most 4 GiB minus one byte,
the protocol limit). The provided
[`deploy/clamav/clamd.conf`](../../deploy/clamav/clamd.conf) already applies
every value below for the default 2 GiB (`2048M`, `MaxScanTime 480000`,
`MaxThreads 10`); if you change `TT_CLAMAV_MAX_SCAN_BYTES`, change the three
size limits of that file too. `make deploy-config-check` has `clamconf` parse
the file and checks its limits and mandatory alerts.

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
`not_scanned_too_large` as well. Give the ClamAV container enough memory and
CPU: the compose file sets 4 GiB and 2 CPUs for clamd (signatures plus the
in-memory spool, see below).

Keep `TT_SCAN_WORKERS` at or below clamd's `MaxThreads` (default 10):
scans queued inside clamd may otherwise time out and count as failed
attempts. The provided deployment sets it to **1**, because of the spool.

## The clamd spool

With `INSTREAM`, clamd first writes the whole stream it receives to its
`TemporaryDirectory` (`/var/tmp/clamav`), then scans that file, and writes
there too the files it extracts from archives. The stream is the
**decrypted** file: on a disk or a Docker volume, the plaintext of every
scanned file would reach the VM backups, and could survive a crash of
clamd (threat model T-44).

The production compose file therefore mounts the spool as a **tmpfs**
(memory), never as a volume:

```yaml
tmpfs:
  - /var/tmp/clamav:size=2304m,mode=0700,uid=100,gid=101
```

- **Sizing: one stream at a time.** 2304 MiB is one stream of
  `TT_CLAMAV_MAX_SCAN_BYTES` (2 GiB, `StreamMaxLength 2048M`) plus 256 MiB
  for the files clamd extracts from it. Hence `TT_SCAN_WORKERS=1` in
  `deploy/.env.example` (and as the compose default): with two scans at once,
  the second one could fill the tmpfs. A scan that fills it fails (clamd
  cannot write its temporary file): the attempt counts against the file,
  which is withheld (`scan_error`) after 3 attempts, never served unscanned.
  Files are scanned one after the other; a large deposit delays the next
  ones, which stay `scanning` meanwhile.
- **Memory.** tmpfs pages count in the memory of the container (cgroup):
  about 1 to 1.5 GiB of signatures, up to 2.25 GiB of spool and the working
  memory of the scan in progress. The compose file sets `mem_limit: 4g` for
  clamd. Measured with ClamAV 1.4.6 and the official signatures: about
  950 MiB after loading, 3.34 GiB at peak while scanning a 2047 MiB stream
  (no out-of-memory kill), which leaves about 650 MiB for the files
  extracted from archives and for the growth of the signatures. If clamd is
  killed for lack of memory (`docker inspect` shows `OOMKilled`), the file
  being scanned loses an attempt (fail-closed, see below): raise
  `mem_limit`.
- **Nothing on disk, nothing left behind.** The tmpfs is emptied at every
  start of the container, so no clean-up is needed after a crash.
- **Swap.** The kernel may write tmpfs pages to swap under memory pressure.
  Run the VM without swap, or with an encrypted swap
  ([Docker installation, prerequisites](../install/docker.md#1-prerequisites)).
- **More parallel scans or a larger limit.** Raise the tmpfs size to
  `TT_SCAN_WORKERS` x `TT_CLAMAV_MAX_SCAN_BYTES` + 256 MiB, and `mem_limit`
  by the same amount, together with `TT_SCAN_WORKERS` or
  `TT_CLAMAV_MAX_SCAN_BYTES` (and the three size limits of `clamd.conf`).

`make deploy-config-check` refuses a rendering where the spool is not a
tmpfs with a size and mode `0700`, where a volume is mounted on it, or where
`TT_SCAN_WORKERS` is not 1; `make deploy-smoke` checks the mount in the
running container.

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

The production compose file does exactly that: clamd runs as the `clamav`
user (UID 100) on the `internal` network (no Internet access, shared only with
TransTeira; PostgreSQL is on its own `db` network), with a read-only root file
system, its signature volume mounted **read-only**, its spool in a tmpfs,
no capability and `no-new-privileges`. A one-shot `clamav-init` container,
running as root without network and with the `CHOWN` and `DAC_READ_SEARCH`
capabilities only, gives the signature volume to the `clamav` user at each
start (`chown -Rh`: symbolic links are never followed).

## Lost notifications

The mails are queued just after the transfer becomes available. If
TransTeira stops in between, the recipients are not notified; the sender sees
the transfer as available, and an administrator can resend the notification
(administration step).

## Signatures

Signatures must stay current (T-46). The official image runs `freshclam` and
clamd in the same container, which would give clamd Internet access. The
production compose file splits them instead:

- **`clamav-update`** runs `freshclam` alone (12 checks a day, the maximum
  ClamAV asks clients to use, configured by
  [`deploy/clamav/freshclam.conf`](../../deploy/clamav/freshclam.conf)). It is
  the only ClamAV container on the `clamav_egress` network, with Internet
  access, and it shares no network with clamd or TransTeira: a file that
  compromised clamd could not be sent out through it.
- **`clamav`** (clamd) reads the shared `transteira_clamav_db` volume
  read-only and reloads new signatures every 10 minutes (`SelfCheck 600`),
  without a second engine in memory (`ConcurrentDatabaseReload no`: scans wait
  a few seconds during a reload).

A container that cannot update its signatures keeps scanning with the old
ones: watch the logs of `clamav-update`
(`docker compose -f deploy/docker-compose.yml logs clamav-update`). At each
start, clamd needs one to two minutes to load the signatures; TransTeira
starts once clamd is healthy.

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
