# CrowdSec integration

Detects brute force and Host scanning from the TransTeira security log, and
lets a CrowdSec bouncer block the offending addresses.

The log format and the event catalogue are specified in
[`docs/operations/security-log.md`](../../docs/operations/security-log.md).

## Files

| File | Destination (CrowdSec config directory, usually `/etc/crowdsec/`) |
|---|---|
| `acquis.d/transteira.yaml` | `acquis.d/transteira.yaml` |
| `parsers/s01-parse/transteira-logs.yaml` | `parsers/s01-parse/transteira-logs.yaml` |
| `scenarios/transteira-bf.yaml` | `scenarios/transteira-bf.yaml` |
| `scenarios/transteira-fqdn-scan.yaml` | `scenarios/transteira-fqdn-scan.yaml` |

The parser relies on `crowdsecurity/non-syslog` (stage `s00-raw`, installed by
default) to turn the `type: transteira` acquisition label into
`evt.Parsed.program`, and on `crowdsecurity/dateparse-enrich` for the
timestamp.

## Installation

1. Give CrowdSec read access to the log. When CrowdSec runs in Docker, mount
   the TransTeira logs volume read-only, for example
   `transteira_logs:/var/log/transteira:ro`, and keep the path of
   `acquis.d/transteira.yaml`. Otherwise point `filenames` at the host path.
2. Copy the files and restart CrowdSec.
3. Check the parsing on a real line:

   ```sh
   cscli explain --type transteira \
     --log '2026-10-20T07:41:00.123Z ip=203.0.113.7 tenant=transfer.entity-a.example.com event=admin_login_failed reason="password"'
   cscli metrics   # "transteira" lines parsed, scenarios overflowing
   ```

## Scenarios

| Scenario | Events | Trigger (per client IP) |
|---|---|---|
| `ed-fr/transteira-bf` | `verification_code_invalid`, `transfer_password_invalid`, `admin_login_failed`, `api_token_invalid`, `deposit_refused`, `rate_limited` | 10 events in a burst, one leaks per minute |
| `ed-fr/transteira-fqdn-scan` | `unknown_fqdn` | 10 events in a burst, one leaks every 30 s |

Both carry `remediation: true`: a decision (ban, 4 h by default profile) is
created on overflow.

TransTeira throttles its own `rate_limited` lines (at most one per client and
scope every 10 s); an unknown-host scan adds about one `unknown_fqdn` line
every 12 s; see
[Log throttling](../../docs/operations/security-log.md#log-throttling). A
flood thus feeds about 6 events per minute into a bucket: still well above
the leak rates above (1 per minute and 2 per minute), so both scenarios
overflow within about two minutes of sustained abuse. Keep the leak speed
below 6 events per minute if you tune them.

## Never ban your own users

CrowdSec bans an IP address, not a person. Behind a corporate NAT, every
internal user shares the same public IPv4 address; with IPv6, a whole site
often shares one `/64`. A burst of failures from any of them would ban
**everyone** behind that address, and a malicious insider could get the
whole company banned on purpose.

Before enabling the scenarios, allowlist:

- the internal IP ranges of **every** tenant (the CIDR lists configured in
  the administration);
- the corporate **egress (NAT) addresses** seen by TransTeira, for each site
  and VPN concentrator;
- monitoring probes (Uptime Kuma, ...).

With CrowdSec 1.6.8 or later, a centralised allowlist also prevents
decisions coming from the community blocklist:

```sh
cscli allowlists create transteira-internal -d "TransTeira internal networks"
cscli allowlists add transteira-internal 192.0.2.0/24 198.51.100.10 2001:db8:10::/48
```

Or, on any version, a whitelist parser (stage `s02-enrich`), for example
`/etc/crowdsec/parsers/s02-enrich/transteira-whitelist.yaml`:

```yaml
name: local/transteira-whitelist
description: "Never ban TransTeira internal networks and NAT egress"
whitelist:
  reason: "internal users and corporate egress"
  ip:
    - "198.51.100.10"
  cidr:
    - "192.0.2.0/24"
    - "2001:db8:10::/48"
```

The ranges above are documentation examples: replace them. Abuse from these
addresses is still visible in the security log and the audit log; it is
handled by TransTeira's own rate limiting and by the administrators, not by
the bouncer.

### IPv6 clients

TransTeira rate-limits IPv6 clients per /64 network, but the shipped ban
works on the exact address logged in `ip=`. A client rotating addresses
inside its /64 is still throttled by TransTeira, yet escapes the firewall
ban. If that matters, ban the /64 instead (for example with a profile that issues `range` decisions on the /64).

## Bouncer

CrowdSec only decides; a bouncer enforces. With the reference Caddy reverse
proxy, use the **Caddy bouncer** (`github.com/hslatman/caddy-crowdsec-bouncer`,
a Caddy module built with `xcaddy`), which rejects banned addresses before
they reach TransTeira, and works per request even behind Docker NAT. The
firewall bouncers (`cs-firewall-bouncer`, iptables or nftables) work as well;
with Docker, they must filter the `DOCKER-USER` chain (see the fail2ban
README for the reason). Nginx, Traefik and Apache have their own bouncers.

## Safety against forged lines

Free-form values (Host header, e-mail address, ...) are attacker-controlled.
They are always quoted and escaped after `event=`; the grok pattern is
anchored at the start of the line and reads the IP from the second token
only, so a value containing `\n... ip=192.0.2.1 ...` cannot target
`192.0.2.1`. Lines without a client address (`ip=-`) are left unparsed. The
pattern is checked by `internal/securitylog/crowdsec_test.go` against
reference and forged lines.
