# Quick install (`install.sh`)

> Version française : [fr/quick-install.md](fr/quick-install.md).

`install.sh` installs TransTeira, ClamAV and the reference Caddy reverse
proxy, all in Docker, on a **blank Debian 12 or 13 server** in a few
minutes. It is an asset of each GitHub release, signed with the same key as
the image, and it installs the signed image of **its own version**, pinned by
digest. For an existing server, a shared reverse proxy or another operating
system, follow the [manual guide](docker.md), which stays the reference.

The example names are fictitious: `admin.transfer.example.com` is the
administration host and `transfer.entity-a.example.com` a tenant. Replace them
with your own.

Contents:

1. [Requirements](#1-requirements)
2. [Download and verify the installer](#2-download-and-verify-the-installer)
3. [Run it](#3-run-it)
4. [What it installs and changes](#4-what-it-installs-and-changes)
5. [First run](#5-first-run)
6. [Upgrade](#6-upgrade)
7. [Uninstall and rollback](#7-uninstall-and-rollback)
8. [Troubleshooting](#8-troubleshooting)

## 1. Requirements

- A **blank server**: Debian 12 (bookworm) or 13 (trixie), amd64 or arm64,
  and root access (`sudo`). The script refuses any other system, and refuses
  a server that already holds a TransTeira installation it did not make
  (a `deploy/.env`, a Caddyfile in `/opt/reverse-proxy` or a container named
  `transteira`).
- **Memory**: at least 8 GiB of RAM (10 GiB with PostgreSQL), as in the
  [manual guide](docker.md#1-prerequisites). Below that the script only
  warns, but ClamAV may then be killed. Run without swap, or with an
  encrypted swap.
- **Disk**: the script stops under 10 GiB free for `/var/lib/docker` and
  warns under 30 GiB. The transferred files are stored there, so plan the sum
  of your tenant quotas.
- **Ports 80/tcp, 443/tcp and 443/udp free** on the server, and reachable from
  the Internet (Let's Encrypt validates through them).
- **DNS**: an `A` record (IPv4) for the administration host name pointing at
  the server, **before** you run the script. **No `AAAA` record**: the
  installation serves IPv4 only, because the Docker network of Caddy has no
  IPv6 and IPv6 clients would otherwise all reach TransTeira with one gateway
  address (shared rate limits, no ban, possibly inside an internal range). The
  firewall and Docker refuse IPv6 on 80 and 443, and the script warns about an
  `AAAA` record. Each tenant
  needs its own record, to create when you create the tenant (section 5). Without
  DNS the script only warns, but Caddy cannot obtain a certificate for the
  name until the record exists.
- **Outbound access** on port 443 to the Docker image registry,
  `download.docker.com` (unless Docker is already installed), `github.com`,
  `deb.debian.org`, `tuf-repo-cdn.sigstore.dev`, `rekor.sigstore.dev`,
  `acme-v02.api.letsencrypt.org` and `database.clamav.net`. The script warns about each one it cannot reach.
- A **password vault outside the server**, for the master key (section 5).

## 2. Download and verify the installer

The script is run as root, so verify it first. The release carries four files:
`install.sh`, `SHA256SUMS` (which lists `install.sh`), its signature
`SHA256SUMS.sigstore.json`, and the public key `cosign.pub`.

```sh
VERSION=2.2.0
BASE=https://github.com/ed-fr/transteira/releases/download/v$VERSION
mkdir transteira-install && cd transteira-install
curl -fsSLO "$BASE/install.sh" -O "$BASE/SHA256SUMS" \
  -O "$BASE/SHA256SUMS.sigstore.json" -O "$BASE/cosign.pub"

# 1. The key: compare with the line "cosign.pub SHA-256 fingerprint" of the README
#    and of SECURITY.md of the project, read on GitHub, not from this download.
sha256sum cosign.pub

# 2. The signature of the sums (required): it is what ties the script to the key
#    of the project. No cosign on the server yet? See the box below.
cosign verify-blob --key cosign.pub --bundle SHA256SUMS.sigstore.json SHA256SUMS

# 3. The script itself:
sha256sum -c --ignore-missing SHA256SUMS
```

Step 2 must print `Verified OK` and step 3 `install.sh: OK`. **Do not skip
step 2**: steps 1 and 3 alone only detect a corrupted download, since
`SHA256SUMS` comes from the same place as `install.sh`.

A blank server has no cosign. Either run the three steps on your workstation
(cosign 3.0 or later) and copy the checked `install.sh` to the server, or fetch
the cosign release the installer itself uses, checked against the SHA-256
written here (read this guide on GitHub, like the fingerprint of step 1):

```sh
# cosign v3.1.4, Linux amd64 (for arm64: cosign-linux-arm64 and
# ade83b7aac62e131cacfe96d958948b2150cc9efec46a570a2649b8e27dedad2).
curl -fsSLo cosign https://github.com/sigstore/cosign/releases/download/v3.1.4/cosign-linux-amd64
echo "424e2c97d0b45fd7a6b608a87f090f35633f4c23ece5f092d48bba11aaf4bbfa  cosign" | sha256sum -c -
chmod 0755 cosign
./cosign verify-blob --key cosign.pub --bundle SHA256SUMS.sigstore.json SHA256SUMS
```

The installer repeats the checks that matter for what it installs: it embeds
`cosign.pub` and checks its fingerprint, downloads cosign pinned by
SHA-256, and verifies the signature and the SBOM attestation of the image by
digest before it pulls it ([Security policy](../../SECURITY.md#verifying-releases)).

`--version` prints the version the script installs, and `--help` lists the
options. The script must be run from a file, not piped from `curl`.

## 3. Run it

Interactive, as root: the script asks a few questions, each with a default.

```sh
sudo bash install.sh
```

| Question | Option | Default |
|---|---|---|
| Administration host name | `--admin-host FQDN` | `hostname -f` when it is a full name |
| Let's Encrypt contact address | `--acme-email ADDRESS` | none (a warning: no expiry notice) |
| PostgreSQL instead of SQLite | `--postgres` | SQLite, which suits most installations |
| System SMTP (disk space alerts) | `--smtp-*` | none |

Unattended (Ansible, cloud-init): `--yes` asks nothing and takes the defaults.
`--admin-host` is then required unless `hostname -f` gives a full name.

```sh
sudo bash install.sh --yes \
  --admin-host admin.transfer.example.com \
  --acme-email ops@example.com
```

All the options:

| Option | Meaning |
|---|---|
| `--admin-host FQDN` | Host name of the administration (lower-cased, validated). |
| `--acme-email ADDRESS` | Contact of the Let's Encrypt account. `--acme-email ""` means none, without question. |
| `--postgres` | PostgreSQL instead of SQLite. See [PostgreSQL](postgresql.md). |
| `--smtp-host HOST` | System SMTP server (`TT_SYSTEM_SMTP_*`), used for the disk space alerts to the super admins. Entities have their own SMTP, set later ([SMTP](smtp.md)). |
| `--smtp-security none\|starttls\|tls` | Default `starttls`. |
| `--smtp-port PORT` | Default 25 with `none`, 587 with `starttls`, 465 with `tls`. |
| `--smtp-from ADDRESS` | Sender address. Required with `--smtp-host`. |
| `--smtp-user NAME` | User name. Refused with `--smtp-security none`; needs `--smtp-password-file`. |
| `--smtp-password-file FILE` | File holding the password; needs `--smtp-user`. It is copied to a Docker secret (`deploy/secrets/system_smtp_password`, owner UID 10001, mode 0400), never to `.env` or the log. |
| `--no-firewall` | Do not install the firewall table. |
| `--no-fail2ban` | Do not install fail2ban and its jails. |
| `--no-auto-updates` | Do not enable the automatic Debian security updates. |
| `--yes`, `-y` | No question. The master key reminder is printed but does not wait. |
| `--dry-run` | Print the plan, the settings added to `.env` and the changed Caddyfile lines. Needs no root and changes nothing. |
| `--upgrade` | Upgrade an installation made by the script (section 6). Refuses `--admin-host`, `--acme-email`, `--smtp-*` and `--postgres`. |
| `--version`, `--help` | Print the version, the help. |

Example with PostgreSQL and an authenticated system SMTP:

```sh
sudo bash install.sh --yes --postgres \
  --admin-host admin.transfer.example.com --acme-email ops@example.com \
  --smtp-host smtp.example.com --smtp-from transteira@example.com \
  --smtp-user transteira --smtp-password-file /root/smtp-password
```

Try `--dry-run` first. The installation takes a few minutes; the first ClamAV
signature download is the longest step. It can be run again after an
interruption: the state is kept in `/opt/transteira/install.conf` and the run
resumes. Once the interrupted run has written its Caddyfile or `.env`, the
second run reuses its answers (host name, ACME address, engine, system SMTP)
and refuses an option that differs. Everything is logged to `/var/log/transteira-install.log` (mode 0600,
no secret is written to it).

## 4. What it installs and changes

Everything the script changes on the server, in order:

1. **Packages**: `ca-certificates`, `curl`, `gpg`, `iproute2`, `tar`, `gzip`,
   `coreutils`, then, unless disabled, `nftables`, `fail2ban` with
   `python3-systemd`, and `unattended-upgrades`.
2. **Docker CE** (`docker-ce`, `docker-ce-cli`, `containerd.io`,
   `docker-compose-plugin`) from the official Docker APT repository, after
   checking the fingerprint of its key (the key file must hold that key only).
   Before that, `/etc/docker/daemon.json` is written with
   `"userland-proxy": false`, so that an IPv6 connection to 80 or 443 is refused
   instead of being relayed to Caddy with the gateway address. If `docker
   compose` already works, Docker is left alone and the repository is not
   added, but Docker Engine 25 and Compose 2.24 or later are required; an
   existing `daemon.json` is never changed (a warning says when it lacks that
   setting). While cloud-init or `apt-daily` holds the apt lock after the first
   boot, the script waits (up to 10 minutes).
3. **cosign**, pinned to a version and SHA-256 baked in the script, in
   `/opt/transteira/bin/cosign`, then the **verification of the image** by
   digest (signature of the index, SBOM attestation of your platform).
4. **`/opt/transteira/deploy`**: the production compose files, the secrets
   (generated by `init-secrets.sh`, among them `secrets/master_key`) and `.env`
   (mode 0600). `.env` sets the image pinned by digest, `TT_ADMIN_HOSTS`,
   `TT_TRUSTED_PROXIES` (Caddy only), `TT_TLS_ASK_ALLOWED_IPS` and `COMPOSE_FILE`,
   so that a plain `docker compose` run from this folder works. With
   `--smtp-user`, a compose overlay mounts the password secret.
5. **`/opt/reverse-proxy`**: Caddy with its Caddyfile, in on-demand TLS mode
   (the certificate of each new entity is obtained when it is first
   requested, no file to edit), and the Docker network `proxy`
   (172.30.0.0/24). Caddy is the only container that publishes ports (80, 443 and
   443/udp).
6. **Containers**: the `transteira` compose project (TransTeira, ClamAV,
   freshclam, PostgreSQL and its backup container if chosen) and the
   `reverse-proxy` project, waited for until healthy.
7. **Host firewall** (unless `--no-firewall`): a dedicated nftables table
   `inet transteira_fw`, loaded by the unit `transteira-firewall.service`
   from `/etc/transteira/firewall.nft`. Incoming traffic is dropped except
   loopback, established connections, essential ICMP, SSH, and 80/tcp, 443/tcp
   and 443/udp over IPv4 (IPv6 is dropped on those ports, see the DNS
   prerequisite). The script never flushes the ruleset: the tables of Docker and
   fail2ban are not touched. The SSH ports kept open are gathered from
   `sshd -T` (`port` and `listenaddress`), the sockets sshd listens on or is
   connected through (`ss`), an active `ssh.socket`, and the SSH session when
   its variables reach the script (`sudo` usually drops them), or 22 if none
   is found. The confirmation question lists them: check that the port you log
   in with is there before answering, or use `--no-firewall`. If SSH listens elsewhere later, change the port in
   `/etc/transteira/firewall.nft` and run
   `systemctl reload transteira-firewall`.
8. **fail2ban** (unless `--no-fail2ban`): the filters and the jails
   `transteira` and `transteira-sso` in `/etc/fail2ban/jail.d/transteira.local`,
   reading `security.log` of the `transteira_logs` volume (bans go through the
   `DOCKER-USER` chain, on 80/tcp, 443/tcp and 443/udp so that HTTP/3 is banned
   too, see [Reverse proxy](reverse-proxy.md) and
   [`integrations/fail2ban/`](../../integrations/fail2ban/README.md)). Add your
   internal ranges and monitoring probes to `ignoreip` in that file, or they
   can be banned. Without `/var/log/auth.log` (no rsyslog), the Debian sshd
   jail is switched to the systemd journal in
   `jail.d/transteira-sshd-journal.local`, otherwise fail2ban would not start.
9. **Automatic updates** (unless `--no-auto-updates`): `unattended-upgrades`
   limited to the Debian security archive, no automatic reboot. Docker CE and
   the images (ClamAV, PostgreSQL, Caddy, pinned by digest) are not updated
   automatically.

Files kept by the script: `/opt/transteira` (`deploy/`, `bin/cosign`,
`cosign.pub`, `install.conf`), `/opt/reverse-proxy`, `/etc/transteira`, the log
`/var/log/transteira-install.log`, and the Docker volumes `transteira_*`.

## 5. First run

When it finishes, the script prints:

- the **setup URL** `https://admin.transfer.example.com/admin/setup` and the
  **setup token**. The token appears on the terminal only, never in the log
  file, and is not printed at all with `--yes` (its output usually ends up in
  an automation log): read it on the server with
  `docker logs transteira 2>&1 | grep 'Setup token'`. It is valid until
  TransTeira restarts; the same command then gives the new one.
- a **reminder to copy the master key** to your vault.

Do these in order:

1. **Save the master key now.** Show it with
   `sudo cat /opt/transteira/deploy/secrets/master_key` (mode 0400) and copy it
   into a password vault **outside the server**. Without it, the files and the
   backups can never be decrypted ([Master key](../operations/master-key.md)).
   In interactive mode the script waits until you type `copied`.
2. **Create the super admin** at the setup URL: token, user name, e-mail address,
   password, then the **TOTP** enrolment (mandatory). Keep the recovery codes
   ([Administration](../operations/admin.md#first-run-setup)). The script never
   creates the super admin: the TOTP secret and the codes stay in your hands.
3. **Create the first entity** in the administration, with the assistant: its FQDN
   (for instance `transfer.entity-a.example.com`), language, SMTP, rules and
   legal texts ([Tenants](../operations/tenants.md)). **Create its DNS record
   first**, pointing at this server: Caddy obtains the certificate on the first
   visit.
4. Configure the **SMTP of the entity** and send the test mail ([SMTP](smtp.md)).
5. Also plan the [backups](../operations/backup.md) of the VM and a copy of the
   secrets kept outside the server.

## 6. Upgrade

With the `install.sh` of the new release, downloaded and verified as in section 2:

```sh
sudo bash install.sh --upgrade
```

Read the [upgrade notes](../operations/upgrade.md) of the version first. The
script then:

1. checks that `/opt/transteira/install.conf` records an installation made by the
   script, and **refuses a downgrade**;
2. verifies the new image (signature, SBOM attestation) and pulls it;
3. creates the secrets the new release needs, if any (`init-secrets.sh` of the
   release: missing files only, existing ones are never changed);
4. checks, in a staging folder, that the compose files of the new release
   load with your `.env`, secrets and Caddyfile; if not, it stops before
   changing anything;
5. **backs up the database**: `transteira backup` with SQLite (the copy goes to
   the `transteira_backups` volume), `pg_dump` with PostgreSQL;
6. keeps the files it is about to replace in `/opt/transteira/previous`
   (deployment folder with `.env`, without the secrets; Caddy compose file),
   then replaces the compose files, the Caddy compose file and the fail2ban
   filters, and points `TRANSTEIRA_IMAGE` of `.env` at the new digest;
7. restarts, waits until TransTeira is healthy and checks that it reports the
   new version. **If that fails, it puts the previous files back and restarts
   the previous version.**

`.env`, the secrets, the SMTP overlay, the Caddyfile and the fail2ban jail are
**kept**. If a release changes `.env` or the Caddyfile (a new variable, a new
Caddy rule), the release notes say so: apply it by hand. `--upgrade` refuses
`--admin-host`, `--acme-email`, `--smtp-*` and `--postgres`: change the
settings in `/opt/transteira/deploy/.env`.

## 7. Uninstall and rollback

There is no uninstall command: the script only installed standard pieces.

- **Rollback of an upgrade**: a failed upgrade rolls back by itself (section 6).
  The previous version and image are recorded in `/opt/transteira/install.conf`
  (`TTI_PREVIOUS_VERSION`, `TTI_PREVIOUS_IMAGE`) and its files in
  `/opt/transteira/previous`. To go back after a successful upgrade, or when the
  previous version refuses a database already migrated by the new one: restore
  the database copy taken by the upgrade
  ([Backups](../operations/backup.md), [Upgrade](../operations/upgrade.md)), copy the
  files of `/opt/transteira/previous/deploy` back to `/opt/transteira/deploy` and
  run `docker compose up -d` in that folder. Running an older `install.sh` is refused.
- **Remove the stack**: in `/opt/reverse-proxy` and `/opt/transteira/deploy`, run
  `docker compose down` (add `-v` in the second one to delete the volumes, which
  **destroys all the transfers**). Then disable
  the firewall with `systemctl disable --now transteira-firewall`, delete
  `/etc/fail2ban/jail.d/transteira*.local` and `/etc/apt/apt.conf.d/52transteira-unattended-upgrades`,
  and remove `/opt/transteira`, `/opt/reverse-proxy` and `/etc/transteira`. Docker
  and the packages stay installed.

## 8. Troubleshooting

- **Log**: `/var/log/transteira-install.log`. When a command fails, the script
  prints the end of the log. The installation can be run again: it resumes from
  `/opt/transteira/install.conf` (state `installing`). The script refuses to run
  on top of a finished installation (use `--upgrade`) or of one it did not make.
- **Slow start of ClamAV**: the first run of freshclam downloads the signatures
  (several minutes), and clamd loads them before it is healthy. The script waits up
  to 25 minutes for the signatures and 15 minutes for each container. If it stops
  with a timeout, look at `docker logs transteira-clamav-update` and
  `docker logs transteira-clamav`, then run the script again.
- **Certificate not obtained** (ACME failure): the DNS record of the host does not
  point at the server yet, or port 80 or 443 is filtered upstream (cloud firewall,
  NAT). Read `docker compose -f /opt/reverse-proxy/docker-compose.yml logs`. Fix the
  DNS, then restart Caddy; Let's Encrypt limits repeated failures, so wait a little
  rather than retrying in a loop. Behind a NAT that forwards 80 and 443 to the server,
  the "does not resolve to this server" warning is harmless.
- **Ports in use**: stop what listens on 80 or 443 (`ss -lntup`), the script checks
  before it changes anything.
- **Locked out of SSH**: the firewall keeps the SSH ports listed before the
  confirmation (section 4, item 7). If SSH listens on another port, or you
  changed it afterwards, use the console of the VM, edit
  `/etc/transteira/firewall.nft` and run `systemctl reload transteira-firewall`.
- **Banned by fail2ban**: `fail2ban-client status transteira`, then
  `fail2ban-client set transteira unbanip <address>`, and add the address to
  `ignoreip`.
- **Settings of the installation**: `/opt/transteira/deploy/.env`. After editing,
  run `docker compose up -d` in that folder. See the
  [environment reference](docker.md#7-configuration-env).
