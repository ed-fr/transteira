# fail2ban integration

Bans, at the firewall of the Docker host, the client addresses that
TransTeira reports in its security log (failed verification codes, wrong
transfer passwords, failed admin logins, invalid API tokens, unknown FQDNs,
refused deposits, rate limiting).

The log format and the event catalogue are specified in
[`docs/operations/security-log.md`](../../docs/operations/security-log.md).

## Files

| File | Destination on the Docker host |
|---|---|
| `filter.d/transteira.conf` | `/etc/fail2ban/filter.d/transteira.conf` |
| `jail.d/transteira.local` | `/etc/fail2ban/jail.d/transteira.local` |

## Installation

1. Make the security log readable from the host: mount the TransTeira logs
   volume (`TT_LOG_DIR`, `/var/log/transteira` in the container) as a named
   volume or a bind mount, and set `logpath` in `transteira.local` to the
   host path of `security.log`.
2. Copy the two files, then check the filter against the real log:

   ```sh
   fail2ban-regex /path/to/security.log /etc/fail2ban/filter.d/transteira.conf
   ```

3. Reload fail2ban and check the jail:

   ```sh
   fail2ban-client reload
   fail2ban-client status transteira
   ```

## Why the `DOCKER-USER` chain

The reverse proxy runs in a container and its ports are published by Docker.
Packets to a published port are DNATed and traverse the `FORWARD` chain, not
`INPUT`: a ban in `INPUT` (the fail2ban default) is silently ineffective.
Docker evaluates the `DOCKER-USER` chain first in `FORWARD` and never flushes
it, so the jail uses an explicit `action = iptables-multiport[...]` with
`chain=DOCKER-USER` (and no separate `banaction`/`chain`/`port`/`protocol`
lines, which that explicit action would override anyway).

In `DOCKER-USER` the destination port is already the **container** port. If
the proxy publishes `8443:443`, list `443`, or switch to `iptables-allports`.
If the proxy runs on the host network, use `chain=INPUT` in the action.

### IPv6 clients

TransTeira rate-limits IPv6 clients per /64 network, but the shipped ban
works on the exact address logged in `ip=`. A client rotating addresses
inside its /64 is still throttled by TransTeira, yet escapes the firewall
ban. If that matters, ban the /64 instead (for example with an `iptables` action that masks the address, or `ip6tables` rules on the prefix).

## Never ban your own users

fail2ban bans an IP address, not a person. Behind a corporate NAT, every
internal user shares the same public IPv4 address; with IPv6, a whole site
often shares one `/64`. Ten failures from any of them (a mistyped
verification code, a forgotten transfer password, a script with a revoked
API token) would ban **everyone** behind that address, and a malicious
insider could get the whole company banned on purpose.

Put in `ignoreip`, before enabling the jail:

- the internal IP ranges of **every** tenant (the CIDR lists configured in
  the administration);
- the corporate **egress (NAT) addresses** seen by TransTeira, for each site
  and VPN concentrator;
- monitoring probes (Uptime Kuma, ...) and loopback.

```ini
# /etc/fail2ban/jail.d/transteira.local (documentation ranges: replace them)
ignoreip = 127.0.0.1/8 ::1
           192.0.2.0/24
           198.51.100.10
           2001:db8:10::/48
```

Abuse from these addresses is still visible in the security log and the
audit log; it is handled by TransTeira's own rate limiting and by the
administrators, not by the firewall.

## Tuning

- `maxretry = 10`, `findtime = 10m`, `bantime = 1h`, with increasing bans
  for repeat offenders (up to one week).
- TransTeira throttles its own `rate_limited` lines (at most one per client
  and scope every 10 s); an unknown-host scan adds about one `unknown_fqdn`
  line every 12 s (see
  [Log throttling](../../docs/operations/security-log.md#log-throttling)).
  A flood therefore yields about 6 lines per minute, not thousands:
  `maxretry = 10` within `findtime = 10m` still bans it in under two
  minutes. Do not lower `findtime` below about 2 minutes, or a sustained
  flood may never reach `maxretry`.
- The `rate_limited` lines of the download stream limits
  (`scope="download_streams"`: too many downloads open at once) never count:
  recipients behind one NAT, or a download manager opening parallel
  connections, reach these limits without any attack. The filter's
  `ignoreregex` matches only the exact line TransTeira writes for them
  (truncated transfer ID, then the scope, nothing after), so a value forged
  elsewhere on the line cannot use it to escape a ban. Every other
  `rate_limited` scope still counts.
- Add trusted networks and monitoring probes to `ignoreip` (see above). Do
  **not** add the reverse proxy: TransTeira logs the real client IP, taken from
  `X-Forwarded-For` only when the request comes from a proxy declared in
  `TT_TRUSTED_PROXIES`. If this variable is wrong, every line carries the
  proxy address and fail2ban would ban the proxy itself.
- To stop banning on an event type (for example `deposit_refused` if
  internal users often try from outside the IP ranges), remove it from
  `_events` in the filter.

## Safety against forged lines

Free-form values (Host header, e-mail address, ...) are attacker-controlled.
The format guarantees that they are always quoted and escaped after the
`event=` token, and the filter only trusts the second token of the line
(`ip=`), anchored right after the leading timestamp. A value such as
`"x\n2026-10-20T07:41:00.000Z ip=192.0.2.1 ..."` cannot ban `192.0.2.1`.
Lines without a client address (`ip=-`) never match. This is checked by
`internal/securitylog/fail2ban_test.go`, which runs the `failregex` of this
filter against reference and forged lines.
