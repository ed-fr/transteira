# Big file trial (human acceptance test)

Before each release, an operator runs a **real trial with very big files behind the
reverse proxy**, in a real browser (specification sections 24.2 and 27.4). This guide describes
the procedure, the expected results, the grid to fill in and what to send back to the developer.

The trial completes the automated 20 GB test (`make bigfile`, the last gate of `make check` when the big-file chain changed, always run by `make check-full`,
described in [test/README.md](../../test/README.md#big-file-test-testbigfile-make-bigfile)). The
automated test proves the server side with a scripted tus client on the developer's workstation;
the trial proves what the automated test cannot: the web interface, a real browser, a real network
with a real cut, the production reverse proxy and the production host.

Reference results of the automated test (20 GiB, SQLite and PostgreSQL, Docker Desktop on a
Windows 11 workstation, client and server on the same machine):

| Measure | Result |
|---|---|
| Upload through Caddy | about 88 to 93 MiB/s |
| Download through Caddy | about 92 MiB/s |
| Upload cut | at 43 % in the middle of a `PATCH`, resumed at the exact byte received (0 bytes sent again) |
| Download cut | at 30 %, resumed with `Range` and `If-Range` |
| SHA-256 | identical everywhere: expected, computed by the server, download page, full download, resumed download |
| Server memory (`anon`) | peak about 97 MiB, no upward trend (limit 256 MiB) |
| Caddy memory | about 17 MiB |
| Antivirus | `not_scanned_too_large` (20 GiB is above the 2 GiB analysis limit) |
| Duration | 1504 s for both engines |

Over a real network, the throughput is bounded by the slowest link (client, Wi-Fi, Internet
access, VM); the other results must be the same.

Contents:

1. [Setup](#1-setup)
2. [Test files](#2-test-files)
3. [Upload with a network cut](#3-upload-with-a-network-cut)
4. [Resume after a page reload](#4-resume-after-a-page-reload)
5. [Downloads and SHA-256 check](#5-downloads-and-sha-256-check)
6. [Server observation](#6-server-observation)
7. [Results grid](#7-results-grid)
8. [What to send back](#8-what-to-send-back)
9. [Troubleshooting](#9-troubleshooting)
10. [Cleaning up and reclaiming disk space](#10-cleaning-up-and-reclaiming-disk-space)

## 1. Setup

**Server.** Install TransTeira as in production, following
[Installing TransTeira with Docker](../install/docker.md), behind the **reverse proxy that will be
used in production** (Caddy, Nginx, Traefik or Apache, see
[Reverse proxy](../install/reverse-proxy.md)). The trial validates that proxy's configuration: run
it on the production host, or on a host with the same proxy and the same network path.

Without the production environment, the reference Caddy configuration
([`integrations/reverse-proxy/caddy/`](../../integrations/reverse-proxy/caddy/README.md)) on a test
VM is acceptable, with `tls internal` and host names that the client machine resolves (a line in
its `hosts` file). Record which proxy was used in the grid.

**Client.** The browser runs on **another machine** than the server: a network cut on the server's
own machine would not cut a loopback connection. Use a laptop on Wi-Fi (or with a network cable
that can be unplugged), with a current Chromium-based browser or Firefox. If possible, repeat the
upload with a second browser.

**Checklist before starting:**

- `docker compose -f deploy/docker-compose.yml ps` shows `transteira` and `clamav` as `healthy`,
  and `https://<tenant FQDN>/healthz` answers `200` with `"status":"ok"` from the client machine.
- A test tenant whose **internal IP ranges include the client** and whose internal domains include
  the trial e-mail address; its SMTP configuration works (test button of the administration), so
  that the verification code and the download link arrive.
- **Per-transfer limit of the tenant at 20 GB** (the super admin raises the ceiling to 20 GB,
  then the limit; [Tenants](tenants.md)) and a **storage quota** of at least 50 GB for the trial.
- **Free disk space on the server**: at least the size of the transfers kept at the same time
  x 1.15, plus 5 GB (the files are stored encrypted, plus the upload in progress). Check with
  `df -h` on the volume of the data directory. The disk alert (85 % by default) must not fire.
- **Free disk space on the client**: the originals, plus one copy for the single-file downloads,
  plus the ZIP archive, plus its extraction (about four times the transfer; delete the downloads
  as you go if needed).
- A stopwatch or the clock of the client, to note the start and end of each phase.
- `TT_LOG_LEVEL=info` (the default). Do not use `debug` during the trial: the logs would be large.

**Duration of the session.** A deposit session lasts `TT_DEPOSIT_SESSION_TTL` (4 hours by default,
counted from the e-mail verification, not extended by activity). The upload needs a valid
session: if the client link is slow (below about 15 Mbit/s for 19 GB), raise the value for the
trial (at most `24h`) or use smaller files, otherwise the upload stops with "Your session has
expired" (the files received so far are kept: identify yourself again and select the same files
to resume).

## 2. Test files

Prepare **2 or 3 files of 5 to 20 GB**, whose total stays within the per-transfer limit (20 GB),
for example **5 GB + 7 GB + 7 GB**. Prefer random content (it cannot be compressed by anything on
the way) or real big files (disk images, videos). Name them clearly (`trial-1.bin`, ...).

Windows (PowerShell), one 7 GiB file of random content (adjust the name and `$size`, a multiple of
64 MiB):

```powershell
$size = 7GB; $path = Join-Path $PWD 'trial-2.bin'
$buf = [byte[]]::new(64MB); $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$fs = [System.IO.File]::Create($path)
try { for ($done = 0L; $done -lt $size; $done += $buf.Length) { $rng.GetBytes($buf); $fs.Write($buf, 0, $buf.Length) } }
finally { $fs.Dispose(); $rng.Dispose() }
```

Linux: `head -c 7G /dev/urandom > trial-2.bin`. macOS:
`dd if=/dev/urandom of=trial-2.bin bs=1m count=7168`.

Do not use `fsutil file createnew` or `truncate`: they create files of zeros (sparse on disk).

**Compute the SHA-256 of each original before the upload** and keep the values: they are the
reference for every later check.

| System | Command |
|---|---|
| Windows (PowerShell) | `Get-FileHash -Algorithm SHA256 .\trial-*.bin \| Format-List Path, Hash` |
| Windows (cmd) | `certutil -hashfile trial-1.bin SHA256` |
| macOS | `shasum -a 256 trial-*.bin` |
| Linux | `sha256sum trial-*.bin` |

`Get-FileHash` prints the hash in upper case, the others and TransTeira in lower case: compare
without regard to case.

## 3. Upload with a network cut

1. Open `https://<tenant FQDN>/`, enter the trial address, then the verification code.
2. Fill in the form: recipient = a mailbox you can read (yours), duration 7 days, no password,
   **without** "Delete the transfer after the first download" (the transfer is downloaded several
   times). Add the 2 or 3 files: the hint shows "Total: ... of 20 GB allowed".
3. Click **Send** and note the start time. The page shows "Sending your files", the overall
   progress ("... of ... sent (...%)") and one line per file; the files are sent one after the
   other.
4. **Cut the network** while the second file is being sent (ideally in its middle): turn off the
   Wi-Fi or unplug the cable for **about one minute**. Note the time and the progress.
5. **Expected during the cut:** the progress stops, then the status changes to "Connection lost,
   trying again…" with "Next attempt in N seconds." and a **Try again now** button. The engine
   detects a failed request at once, or a stalled one after 45 seconds without progress, then
   retries after 1, 2, 4, 8... seconds (at most 30 seconds between attempts).
6. **Restore the network** and note the time. The browser's "online" event triggers an immediate
   attempt: the engine asks the server where to resume, and the upload continues. It may take up
   to about a minute: the server first has to notice that the interrupted request is dead (its
   idle timeout, `TT_UPLOAD_IDLE_TIMEOUT`, 60 seconds) and release it; the engine waits for that
   without counting it as a failure.
7. **Expected after the cut:** the progress resumes **from where it stopped** (at most the last
   few megabytes are sent again, never the whole file, never the files already sent). Note the
   progress at the resume.
8. Optional, a longer cut (5 minutes): after 10 consecutive failures (about 3 minutes), the engine
   pauses and shows "The connection keeps failing, so the upload is paused. Check your network
   connection, then resume: it continues where it stopped." Restore the network and click
   **Resume**: the upload continues where it stopped.
9. At the end: "All files sent", then "Analysing the files" while the antivirus works. Files
   above 2 GB are not analysed (`TT_CLAMAV_MAX_SCAN_BYTES`, see [Antivirus](antivirus.md)), so
   this step is short. Note the end time. The final screen "Transfer sent" lists each file with
   its SHA-256 and the warning "This file could not be analysed by the antivirus: it is delivered
   and the recipients are told so."
10. **Compare the SHA-256 shown on the final screen with those of the originals.**

The **Pause** and **Resume** buttons can also be tried during the upload: the upload continues
where it stopped.

Do not close the tab during the upload: the browser asks for confirmation before leaving, and
closing the tab loses the information needed to resume (section 4). An abandoned upload keeps its quota reservation until it expires
(`TT_UPLOAD_TTL`, 24 hours after the last activity), then is deleted by the cleanup task.

## 4. Resume after a page reload

A second transfer, smaller (one or two files of 5 GB are enough):

1. Start the upload, and in the middle of a file **reload the page** (F5), confirming that you
   want to leave.
2. **Expected:** in the same tab, the page shows "Resume the interrupted upload": "An upload was
   interrupted. Select the same files again to continue where it stopped.", with the list of the
   files of the interrupted transfer.
3. Select the same files again (**Select the same files again**). They are recognised by their
   name, size and last modification date; a missing one is listed ("These files are still
   missing: ..."). Once all are there: "All the files needed are selected." and **Continue the
   upload**.
4. **Expected:** the upload continues where it stopped (the progress starts again from the
   percentage reached before the reload, not from 0), then the transfer finishes normally.
5. Check also the other choice once: **Start a new transfer instead** discards the interrupted
   transfer (cancelled on the server) and shows an empty form.

Only the transfer identifier and the fingerprints of the files (name, size, date) are kept in the
browser, for this tab only (`sessionStorage`): the resume works after a reload, not in another tab
or after the browser is closed. It also needs the deposit session to still be valid.

## 5. Downloads and SHA-256 check

Open the link of the notification e-mail received by the recipient (preferably on the client
machine, or on another one: the download page needs no IP rule). With several recipients, each one
has their own link (and a verification code if the option was chosen): download from at least two
of them. If time allows, also send one large folder tree by drag and drop and check that the
tree is preserved in the file list and in the ZIP.

1. **Expected on the page:** the sender, the expiry date, "Total: 3 files, ...", for each file its
   size, its **SHA-256 fingerprint** (with a copy button) and the notice "Not analysed by the
   antivirus: this file is too large to be analysed.", and above the list "Some files could not be
   analysed by the antivirus. Open them only if you trust the sender."
2. **Compare the SHA-256 shown on the page with those of the originals** (and with those of the
   e-mail).
3. **Download each file** with its **Download** link. Note the time and the speed shown by the
   browser's download manager. The browser must save the file (never display it), under its
   original name.
4. Optional: cut the network during a single-file download, then restore it and click **Resume**
   in the browser's download list. The download continues where it stopped (the server supports
   byte ranges). Some browsers restart the download from the beginning instead: note what
   happened.
5. **Download all files (ZIP).** The archive is generated on the fly, without compression: its
   size, announced in advance, is close to the total of the files. An interrupted ZIP download
   cannot be resumed: it starts again from the beginning.
6. **Compute the SHA-256 of every downloaded file** (same commands as in section 2), then
   **extract the ZIP archive** and compute the SHA-256 of the extracted files. Above 4 GB, the
   archive uses the ZIP64 format: if the extractor built into the system refuses it, use 7-Zip or
   `tar -xf archive.zip` (built into Windows 10 and later, macOS and Linux).
7. **Expected:** every SHA-256 is identical: original = final screen of the upload = download page
   = single-file download = file extracted from the ZIP.

## 6. Server observation

During the upload and the downloads, on the server:

```sh
docker stats transteira transteira-clamav
docker compose -f deploy/docker-compose.yml logs -f transteira
```

And after the trial:

```sh
docker compose -f deploy/docker-compose.yml logs --since 4h transteira | grep -E '"level":"(ERROR|WARN)"'
docker inspect transteira --format 'OOMKilled={{.State.OOMKilled}} restarts={{.RestartCount}} health={{.State.Health.Status}}'
```

**Expected:**

- **No `ERROR` line** in the TransTeira log. A `WARN` line starting with `upload reset:` (the
  server restarted an upload from offset 0) must not appear either: report it.
- The container is never restarted or killed (`OOMKilled=false restarts=0 health=healthy`), and
  `/healthz` stays `200` throughout.
- **Memory:** the `MEM USAGE` column of `docker stats` counts the page cache of the files written
  and read; it can climb close to the 1 GiB limit of the container and stay there. That is normal:
  the kernel reclaims it on demand. The memory that matters is the server's own (`anon`), about
  100 MiB in the automated test. On a Linux host with cgroup v2, it can be read directly:

  ```sh
  cat /sys/fs/cgroup/system.slice/docker-$(docker inspect -f '{{.Id}}' transteira).scope/memory.stat | grep -E '^anon '
  ```

  (the path depends on the cgroup driver; with `cgroupfs`, use
  `/sys/fs/cgroup/docker/<id>/memory.stat`). Note the highest value seen: expected below 256 MiB,
  with no steady growth from one file to the next.
- **CPU:** encryption and SHA-256 use about one core during an upload, decryption about one core
  per download. clamd stays idle for files above 2 GB.
- **Proxy:** its memory stays stable (no buffering of requests or responses) and its disk does not
  fill up; its access log shows the tokens masked (`/d/…`, `/api/v1/downloads/…`).
- The tenant's audit log (administration) shows the deposit and the downloads with the **client's
  real IP address**, not the proxy's.

## 7. Results grid

Copy this grid and fill it in, one column per transfer (add rows for other browsers).

| Item | Transfer 1 (network cut) | Transfer 2 (reload) |
|---|---|---|
| Date, TransTeira version (`/healthz`) | | |
| Reverse proxy and version, host (production or test VM) | | |
| Database engine (SQLite / PostgreSQL) | | |
| Client: OS, browser and version, network (Wi-Fi, cable, VPN) | | |
| File sizes | | |
| Upload: start, end, duration, average throughput | | |
| Cut: duration, progress before, progress at the resume | | |
| Automatic resume OK (yes / no, details) | | |
| Resume after a longer cut with **Resume** (yes / no / not tried) | | |
| Reload resume OK (yes / no / not tried) | | |
| SHA-256 originals = final screen = download page | | |
| Single-file downloads: duration and throughput of each | | |
| Single-file download resume (yes / restarted / not tried) | | |
| ZIP download: size, duration, throughput | | |
| SHA-256 of the downloads and of the extracted files OK | | |
| Antivirus status shown (expected: not analysed, too large) | | |
| Server memory peak: `anon` (if read) and `docker stats` | | |
| Proxy memory peak | | |
| Restarts, OOM, `/healthz` not `200` | | |
| `ERROR` / `WARN` lines in the TransTeira log (count) | | |
| Real client IP in the audit log | | |
| Other remarks (messages seen, anything unexpected) | | |

The trial **passes** when, for every transfer: the automatic resume and the reload resume continue
where the upload stopped, every SHA-256 is identical, the server is never restarted, the log has
no `ERROR` and the server's memory stays bounded.

**Trial record.** The V1 acceptance trial was run and validated by the operator on 2026-10-25,
before version 1.0.0: build `0.0.0-dev+267b890`, SQLite, reference Caddy (`tls internal`) on a
Docker Desktop workstation, files of several GB uploaded from a browser with a network cut and an
automatic resume, then downloaded, every SHA-256 matching. Docker Desktop hides the client IP
(every client appears as the gateway of the proxy network), so the real client IP item of the grid
remains to be checked on the production host. The changes made after that build (antivirus
outage alert, default deadline before routing, which the streaming routes clear) are covered by
`make check` on the release commit, including the automated 20 GB test and
`TestDefaultDeadlineSparesStreaming`.

The 1.1.0 trial was run and validated by the operator on 2026-10-31: build `0.0.0-dev+bd68cb9`,
the 1.0 trial installation upgraded in place (9 migrations applied at startup), SQLite, reference
Caddy (`tls internal`) on the same Docker Desktop workstation. A 7.9 GB file was uploaded from a
browser with a network cut and an automatic resume, two recipients downloaded with their own
links after verifying their address, a folder kept its tree in the file list and in the ZIP, and
every SHA-256 matched. The browser uploaded at about 55 MiB/s (8081 MiB in 148 s, over HTTP/2,
32 MiB chunks, pauses between chunks of a few milliseconds): this is the browser's own upload
rate, the server and the proxy are not the limit (the automated client reaches 87 to 97 MiB/s
through the same proxy, with 32 MiB chunks too).

## 8. What to send back

Send to the developer:

- the **filled grid**;
- the **`ERROR` and `WARN` lines** of the TransTeira log for the trial period, and around each
  cut the lines of the minute before and after (`docker compose ... logs --since ... --until ...
  transteira`);
- the `docker stats` values noted (or a screenshot), the output of `docker inspect` above, and the
  `anon` values if read;
- for a failure: the error message shown by the page (screenshot), its time, the proxy's error log
  for the same minute, and the HTTP status of the failing requests (browser developer tools,
  Network tab: status and headers only, no request body).

**Remove the secrets before sending:** download links and tokens (`/d/…`, `/i/…`,
`/api/v1/downloads/…`, `/api/v1/invitations/…`), upload identifiers (`upl_…`), cookies, CSRF
tokens, `Authorization` headers, API tokens, the setup token, verification codes, SMTP passwords
and the master key (it is never logged; never send it). Replace real e-mail addresses and public
IP addresses with placeholders if the report leaves your organisation.

## 9. Troubleshooting

Most failures with big files come from the reverse proxy. Each configuration of
[`integrations/reverse-proxy/`](../../integrations/reverse-proxy/README.md#common-requirements)
implements the common requirements; compare yours with the provided one
([Caddy](../../integrations/reverse-proxy/caddy/README.md),
[Nginx](../../integrations/reverse-proxy/nginx/README.md),
[Traefik](../../integrations/reverse-proxy/traefik/README.md),
[Apache](../../integrations/reverse-proxy/apache/README.md)).

| Symptom | Likely cause | Fix |
|---|---|---|
| Upload stops at once with "A file is larger than the size declared or allowed" (`413` in the Network tab, from the proxy) | Request body size limit of the proxy (Nginx `client_max_body_size`, Apache `LimitRequestBody`, Traefik buffering middleware `maxRequestBodyBytes`) | No size limit at the proxy: TransTeira enforces the per-transfer limit itself. |
| Upload or download cut after a fixed time (60 s, 5 min...), `502` / `504`, then repeated "Connection lost" | Proxy timeout on the whole request or between two reads (Nginx `proxy_read_timeout` / `proxy_send_timeout`, Apache `Timeout` / `ProxyTimeout`, Traefik `readTimeout` / `writeTimeout` of the entry point) | Disable the whole-request deadlines, set the idle timeouts to one hour, as in the provided configurations. |
| Progress jumps quickly then waits long at each chunk, proxy memory or disk grows, resume sends the same bytes again | Request buffering (Nginx `proxy_request_buffering on`, Traefik buffering middleware) | Disable request buffering. |
| Download starts only after a long delay, or the ZIP archive never starts | Response buffering (Nginx `proxy_buffering on`), or compression of the downloads | Disable response buffering; never compress `/api/v1/uploads…` and `/api/v1/downloads/…`. |
| Single-file download cannot be resumed | Compression or a response transformation at the proxy (byte ranges broken) | Exclude downloads from compression. |
| "Deposits are only possible from the internal network..." although the client is internal | The proxy's address is not in `TT_TRUSTED_PROXIES`, or the proxy does not forward the client IP; the audit log shows the proxy's IP | [Reverse proxy, `TT_TRUSTED_PROXIES`](../install/reverse-proxy.md#tt_trusted_proxies). |
| "The server has run out of storage space" (`507`) | Tenant quota reached, or server disk full | Raise the quota, delete old trial transfers, free disk space. |
| "Your session has expired" during a long upload | `TT_DEPOSIT_SESSION_TTL` shorter than the upload (section 1) | Identify yourself again and select the same files; raise the value for slow links. |
| Upload stalls although the network is fine, behind a company proxy, VPN, CDN or WAF | An intermediate device with its own body size, buffering or timeout limits | Test without it, or configure it like the reverse proxy. |
| `ERROR` lines in the log, container restarts | Server problem | Send the lines and the grid (section 8). |

## 10. Cleaning up and reclaiming disk space

**On the server.** Delete the trial transfers from the administration (tenant operations,
Transfers: delete). Deletion destroys the key of each file (cryptographic erasure) and frees the
quota at once; otherwise they expire after their duration. Restore the per-transfer limit, the
quota and `TT_DEPOSIT_SESSION_TTL` if they were changed for the trial.

**On the client.** Delete the originals, the downloads and the extracted files.

**Docker Desktop (developer workstation, after `make bigfile` or a local trial).** Deleting
volumes frees space inside the Docker disk image, but the image file on the host does not shrink
by itself.

1. Remove what the tests left and the unused data:

   ```sh
   make bigfile-clean                          # transteira-bigfile-* left by BIGFILE_KEEP=1
   bash scripts/bigfile.sh clean --signatures  # also the ClamAV signature cache volume
   docker system df                            # what uses the space
   docker builder prune                        # build cache
   docker image prune                          # dangling images
   ```

   Do not run `docker volume prune` or `docker system prune --volumes` on a machine that holds a
   real installation: they delete its volumes (database, encrypted files).

2. Shrink the disk image on Windows (WSL2): quit Docker Desktop, run `wsl --shutdown`, then
   compact the virtual disk (`docker_data.vhdx` under `%LOCALAPPDATA%\Docker\wsl\disk\`, or
   `ext4.vhdx` under `%LOCALAPPDATA%\Docker\wsl\data\` with older versions, or the custom folder
   set in Settings > Resources). With the Hyper-V module (Windows Pro), in an administrator
   PowerShell:

   ```powershell
   Optimize-VHD -Path "$env:LOCALAPPDATA\Docker\wsl\disk\docker_data.vhdx" -Mode Full
   ```

   Without it, with `diskpart` in an administrator prompt: `select vdisk file="<path>"`,
   `attach vdisk readonly`, `compact vdisk`, `detach vdisk`.

   Docker Desktop's Troubleshoot > **Clean / Purge data** also gives the space back, but deletes
   **every** image, container and volume.
