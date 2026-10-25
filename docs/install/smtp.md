# SMTP

> Version française : [fr/smtp.md](fr/smtp.md).

TransTeira sends two kinds of mail:

- **tenant mails** (verification codes, transfer notifications, confirmations,
  invitations, antivirus and quota alerts), through **the SMTP settings of each
  tenant**, set in the administration (CLAUDE.md section 12.1);
- **system mails** (the disk space alert to the super admins), through the
  **system SMTP server** set by environment variables
  ([below](#system-smtp-for-the-alerts)).

Three kinds of server are supported, for both: an authenticated SMTP server
over TLS, an unauthenticated relay on the internal Docker network, and, as a
special case of the latter, a relay to Microsoft 365 through Microsoft Graph.

## Tenant SMTP settings

Each tenant has its own settings (**Mail (SMTP)** screen of the tenant,
super admin or delegated admin of the tenant):

| Field | Notes |
|---|---|
| SMTP server, port | Host name or IP address, port 1 to 65535. |
| Connection security | `starttls` (usually port 587): the upgrade is mandatory, a server that does not offer STARTTLS is an error, never a silent fallback to clear text. `tls`: implicit TLS from the first byte (usually 465). `none`: plain TCP, for a relay on the internal Docker network only. |
| Username, password | Optional (`AUTH PLAIN`). Refused with `none`: credentials never travel in clear. |
| Sender address, sender name | The `From` address (for example `transfer@entity-a.example.com`) and an optional display name. |

- **Certificates** are checked against the CA bundle of the image (public
  CAs). A server with a self-signed or private-CA certificate is refused.
- **The password is encrypted at rest**: sealed by the master key, never
  shown again and never logged. When the
  host, the port or the username change, the password must be entered again.
- **Test button**: sends a test mail with the saved settings and shows the
  SMTP stage reached (connection, TLS, authentication…) with the server's
  answer; 5 tests per 10 minutes per admin and tenant. A mail accepted by the
  server may still be filtered further down.
- **DNS check**: an indicative check of SPF, DMARC and DKIM for the domain of
  the sender address ([below](#spf-dkim-and-dmarc)).

Until a tenant has working SMTP settings, it cannot send any mail, so nobody
can verify an address on it. More: [Tenants, SMTP](../operations/tenants.md#smtp)
and the [delegated administrator guide](../user/en/delegated-admin.md).

## Authenticated SMTP server

The usual case: a mail provider or your own mail server reachable over the
Internet or your network. Choose `starttls` on port 587 (or `tls` on 465),
with a username and a password dedicated to TransTeira, allowed to send as
the tenant's sender address.

The TransTeira container reaches the Internet through the `proxy` network
(the `internal` network has no Internet access). If your firewall filters
outgoing traffic, allow the Docker host to reach the SMTP servers of the
tenants.

## Unauthenticated relay on the internal Docker network

TransTeira accepts an SMTP relay **without authentication or encryption**
(security `none`), for example a relay container that forwards to your mail
system or to Microsoft Graph. Since nothing protects the traffic, the relay
must sit on a Docker network shared only with TransTeira, never across an
untrusted network.

**Network.** Put the relay on a dedicated network shared with the
`transteira` service, plus whatever network it needs to reach its upstream.
Do not edit the provided compose files: add a file of your own next to them,
for example `deploy/docker-compose.mail.yml`:

```yaml
# deploy/docker-compose.mail.yml (your file, not part of the repository)
services:
  smtp-relay:
    image: <relay image>@sha256:<digest>   # pin it
    container_name: transteira-smtp-relay
    restart: unless-stopped
    networks:
      - mail          # reachable by TransTeira only
      - mail_egress   # to reach its upstream (Internet or your mail server)
    # Relay settings and upstream credentials: see the relay's documentation.
    # Keep secrets in Docker secrets, never in plain environment values.

  transteira:
    networks:
      - mail

networks:
  mail:
    internal: true
  mail_egress: {}
```

```sh
docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.mail.yml up -d
```

(Add it to `COMPOSE_FILE` in `deploy/.env` to avoid repeating the `-f`
options, and keep the same list for every later command, including
upgrades.)

Then, in the tenant settings: server `smtp-relay` (the service name, resolved
by Docker), port `25` (or the relay's port), security **None**, no username.

**`TT_SMTP_DENY_NETWORKS`.** The SMTP server of a tenant is typed by an
admin, so TransTeira checks the address it resolves to, at each connection,
against `TT_SMTP_DENY_NETWORKS` (protection against server-side request
forgery and DNS rebinding). The default denies loopback, link-local
(including the cloud metadata addresses), `0.0.0.0/8` and `::/96`, but **not
the private ranges** (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`): a
relay on a Docker network works with the default, nothing has to be changed.
Consequences:

- a relay on loopback (`127.0.0.1`, or `localhost`) is refused for a tenant:
  use a container on a Docker network;
- if you set the variable, the value **replaces** the default: repeat the
  default list and append your own networks (see `.env.example`);
- **the provided deployment sets it**: `deploy/.env.example` repeats the
  default list and appends the fixed subnets of the stack, so that the SMTP
  server of a tenant can reach neither clamd, nor PostgreSQL, nor the reverse
  proxy and the other services of the shared network: the `proxy` subnet
  (`172.30.0.0/24`), `INTERNAL_SUBNET` (`172.31.10.0/24`, clamd) and
  `DB_SUBNET` (`172.31.11.0/24`, PostgreSQL). If you change one of these
  subnets, change the list too (`make deploy-config-check` verifies the
  provided files). A tenant relay must therefore sit on a network of its
  own, like the `mail` network above, never on `proxy` or `internal`;
- the system SMTP server is an installation setting and is **not** subject
  to this list.

**Shared relay and sender addresses.** An unauthenticated relay sends
whatever it receives. If several tenants use the same relay, the admin of one
tenant can type any sender address in its settings, including an address of
another tenant. Restrict, at the relay or at its upstream, the sender
addresses it accepts to those of your tenants, or run one relay per tenant.

## Microsoft 365 through Microsoft Graph

Microsoft 365 is reachable with a relay container that receives SMTP from
TransTeira and sends each message with the Microsoft Graph API (an
application registered in Microsoft Entra ID, with the `Mail.Send`
application permission). Several open source relays do this; follow the
documentation of the one you choose, and set it up as in the
[previous section](#unauthenticated-relay-on-the-internal-docker-network).

For each tenant, check in Microsoft 365:

1. **The sender address exists** as a mailbox (a shared mailbox is enough)
   in a domain accepted by your Microsoft 365 organisation, for example
   `transfer@entity-a.example.com`.
2. **DKIM is enabled in Microsoft 365 for each tenant domain**, not only for
   the default domain: in the Microsoft Defender portal (email authentication
   settings, DKIM), select each custom domain, publish the two `CNAME`
   records it shows (`selector1._domainkey` and `selector2._domainkey`) and
   enable signing. Without it, mail from that domain fails DMARC alignment
   and is likely to be rejected or classified as spam.
3. **The sender address is authorised in the Graph application.** The
   `Mail.Send` application permission allows sending as **any** mailbox of
   the organisation by default: limit the application to the sender
   mailboxes of the tenants, ideally to those mailboxes only, with an
   Exchange Online application access policy (or role-based access control
   for applications, its successor). For example, with a mail-enabled
   security group `transteira-senders@example.com` containing the sender
   mailboxes:

   ```powershell
   New-ApplicationAccessPolicy -AppId <application (client) ID> `
     -PolicyScopeGroupId transteira-senders@example.com `
     -AccessRight RestrictAccess `
     -Description "TransTeira relay: tenant sender mailboxes only"
   Test-ApplicationAccessPolicy -AppId <application (client) ID> -Identity transfer@entity-a.example.com
   ```

   When you add a tenant, add its sender mailbox to the group.
4. **SPF, DKIM and DMARC** are published for each domain (below). For
   Microsoft 365, SPF includes `include:spf.protection.outlook.com`, and the
   DKIM selectors to type in the TransTeira DNS check are `selector1` and
   `selector2`.

Keep the client secret (or certificate) of the Graph application in a Docker
secret of the relay, and in your password vault.

## SPF, DKIM and DMARC

Each sending domain (the domain of each tenant's sender address, and of the
system sender) needs, **before production**:

| Record | Example | Role |
|---|---|---|
| SPF (`TXT` on the domain) | `v=spf1 include:spf.protection.outlook.com -all` | Lists the servers allowed to send for the domain. |
| DKIM (`TXT` or `CNAME` on `<selector>._domainkey`) | given by your mail provider | Signs each message. |
| DMARC (`TXT` on `_dmarc`) | `v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com` | Tells receivers what to do when SPF or DKIM fail alignment. |

TransTeira does not sign mail itself: DKIM is applied by the server or the
relay's upstream that sends the mail on the Internet.

The **DNS check** of the tenant SMTP screen looks up these records for the
domain of the sender address and reports each one as correct, to be checked,
missing or failed. DKIM selectors cannot be discovered: type up to 5 (for
example `selector1, selector2` for Microsoft 365). The check is indicative:
it reads public DNS, it does not send a message. Confirm with a test mail
and the authentication results in its headers.

## System SMTP for the alerts

The disk space alert concerns the whole instance, so it is not sent through
a tenant's settings but through the **system SMTP server**, set in
`deploy/.env`:

| Variable | Role |
|---|---|
| `TT_SYSTEM_SMTP_HOST` | Server name or address. Empty (default): no system mail, the disk alert only shows in the administration, the audit log and the application log. |
| `TT_SYSTEM_SMTP_PORT` | Default 25 with `none`, 587 with `starttls`, 465 with `tls`. |
| `TT_SYSTEM_SMTP_SECURITY` | `starttls` (default), `tls` or `none` (unauthenticated relay on the internal network). |
| `TT_SYSTEM_SMTP_FROM`, `TT_SYSTEM_SMTP_FROM_NAME` | Sender address (required) and display name. |
| `TT_SYSTEM_SMTP_USERNAME`, `TT_SYSTEM_SMTP_PASSWORD_FILE` | Credentials, both or neither, refused with `none`. The password is only read from a file (a Docker secret), never from a variable. |

With the relay of the examples above:

```sh
TT_SYSTEM_SMTP_HOST=smtp-relay
TT_SYSTEM_SMTP_PORT=25
TT_SYSTEM_SMTP_SECURITY=none
TT_SYSTEM_SMTP_FROM=transteira@example.com
```

`TT_SMTP_DENY_NETWORKS` does not apply to the system server: it may be a
relay on any internal network. An invalid configuration stops the start-up.
There is no test button for the system server: check the values carefully,
and watch the application log (`docker compose logs transteira`), which
reports a failed delivery.
For an authenticated server and the Docker secret of its password, see
[Administration, system SMTP server](../operations/admin.md#system-smtp-server).
