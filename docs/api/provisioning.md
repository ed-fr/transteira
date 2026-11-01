# Provisioning API guide

This guide is for **managed service providers** (MSPs) that run TransTeira for several
organisations and want to create entities (tenants) from a script instead of the
administration interface. It covers the provisioning token, how the super admin creates it, the
three operations of the provisioning API, ready-to-use `curl` and PowerShell 7 examples, and the
errors you may meet.

The reference is the OpenAPI specification (`/api/openapi.yaml`, tag **Provisioning**). Error
codes are described in [errors.md](errors.md). The examples use fictitious hosts:
`admin.example.com` for the administration (the provisioning API is served there and nowhere
else) and `*.transfer.example.com` for the entities.

## Contents

- [1. What a provisioning token is](#1-what-a-provisioning-token-is)
- [2. Create a provisioning token (super admin)](#2-create-a-provisioning-token-super-admin)
- [3. Create an entity](#3-create-an-entity)
- [4. List and follow your entities](#4-list-and-follow-your-entities)
- [5. Errors](#5-errors)
- [6. Certificates for the new tenants](#6-certificates-for-the-new-tenants)
- [7. What happens next, and who is responsible for what](#7-what-happens-next-and-who-is-responsible-for-what)

## 1. What a provisioning token is

A provisioning token (`ttp_` followed by 43 characters) is an instance-wide credential, created
by the super admin and handed to the MSP. It is **not** an API token: the per-entity API tokens
(`tt_...`, see [integration.md](integration.md)) deposit files and are never accepted here, and
a provisioning token is never accepted on an entity's endpoints.

- **Host.** The provisioning API answers on the administration host only
  (`https://admin.example.com/api/v1/provisioning/...`). On an entity's FQDN it answers
  `404 not-found`.
- **Credential.** Only the header `Authorization: Bearer ttp_...` authenticates a request. A
  session cookie (an admin session included) is ignored and no CSRF token is needed.
- **Scope.** The token carries limits chosen by the super admin, and a request outside them is
  refused with `403 provisioning-scope-exceeded`:
  - the **IP ranges** (`allowedCidrs`) it may be used from, mandatory, never `0.0.0.0/0` nor `::/0`;
  - the **FQDN suffixes** (`allowedFqdnSuffixes`) of the entities it may create, mandatory
    (`.transfer.example.com` accepts `entity-c.transfer.example.com`, never
    `eviltransfer.example.com` nor the suffix itself);
  - the highest **storage quota** of an entity (`maxStorageQuotaBytes`) and, optionally, the
    highest **limit per transfer** (`maxTransferBytes`, at most 20 GiB);
  - the highest number of **entities** it may have created (`maxTenants`): the entities that
    still exist count, including one being deleted until its deletion completes (the
    `tenantsCreated` shown to the super admin counts the same way, although the list of section 4
    already leaves such an entity out);
  - an optional **expiry date**.
- **What it sees.** Only the entities it created, with their setup state and whether their
  delegated admin activated the account. It sees no transfer, no address, no configuration, and
  it can neither change nor delete an entity.
- **Storage.** TransTeira keeps only the SHA-256 fingerprint of the secret.

## 2. Create a provisioning token (super admin)

Only the super admin creates, lists and revokes provisioning tokens, in the administration
(**Provisioning tokens**) or through `POST /api/v1/admin/provisioning-tokens` with an admin
session. The creation asks for a **TOTP re-confirmation**: a current TOTP code (or a recovery
code), even though you are signed in. A code already used for the login cannot be used again in
the same 30-second step; a wrong code counts towards the same lockout as the login.

Fill in the scope described above. Prefer a single stable address for the ranges
(`198.51.100.10/32`), a suffix dedicated to the MSP's entities, and an expiry date.

The secret is shown **once**, at the creation. If it is lost, create a new token and revoke the
old one. Revoking is immediate and does not affect the entities the token already created. The
list shows the prefix of each token, its last use and the number of entities it created.
Every creation is mailed to all the super admins through the system SMTP and sent to the
instance-wide webhooks as `provisioning_token.created` (name, prefix, creator, IP and scope, never
the secret), so that a token created from a stolen session does not go unnoticed.

Give the secret to the MSP through a secure channel, never by plain e-mail or chat.

## 3. Create an entity

`POST /api/v1/provisioning/tenants` creates an entity and its first delegated admin in one
transaction. The entity is created in the **setup** state (see
[below](#7-what-happens-next-and-who-is-responsible-for-what)).

| Field | Required | Remarks |
|---|---|---|
| `name` | yes | Display name, 1 to 100 characters. |
| `fqdn` | yes | Must end with one of the suffixes of the token. |
| `defaultLanguage` | yes | `fr` or `en`. |
| `storageQuotaBytes` | yes | At most the `maxStorageQuotaBytes` of the token. |
| `maxTransferBytes` | no | At most the cap of the token; default the cap of the token, else 20 GiB. |
| `backgroundPreset` | no | Identifier of a background of the library. |
| `delegatedAdmin` | yes | `username`, `email`, `language` of the first delegated admin. |

The request accepts nothing else: a `setupState`, a role or any unknown field is a
`400 validation-failed`.

**curl** (a bash script; the secret is read from a file readable by the service account only,
never passed as an argument):

```bash
TT_PROVISIONING_TOKEN=$(< ~/.config/transteira/provisioning-token)

curl -sS --fail-with-body -X POST \
  -H "Authorization: Bearer ${TT_PROVISIONING_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{
        "name": "Entity C",
        "fqdn": "entity-c.transfer.example.com",
        "defaultLanguage": "fr",
        "storageQuotaBytes": 549755813888,
        "delegatedAdmin": {
          "username": "admin.entity-c",
          "email": "it@entity-c.example.com",
          "language": "fr"
        }
      }' \
  https://admin.example.com/api/v1/provisioning/tenants
```

**PowerShell 7**:

```powershell
$token = (Get-Content -Raw "$HOME/.config/transteira/provisioning-token").Trim()
$body = @{
    name              = 'Entity C'
    fqdn              = 'entity-c.transfer.example.com'
    defaultLanguage   = 'fr'
    storageQuotaBytes = 549755813888
    delegatedAdmin    = @{
        username = 'admin.entity-c'
        email    = 'it@entity-c.example.com'
        language = 'fr'
    }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Method Post -Uri 'https://admin.example.com/api/v1/provisioning/tenants' `
    -Authentication Bearer -Token (ConvertTo-SecureString $token -AsPlainText -Force) `
    -ContentType 'application/json' -Body $body
```

The answer is `201`:

```json
{
  "id": "ten_01JAB00000000000000ENT1TYC",
  "name": "Entity C",
  "fqdn": "entity-c.transfer.example.com",
  "setupState": "setup",
  "createdAt": "2026-10-31T09:12:00Z",
  "delegatedAdminActivated": false
}
```

Each token may make at most **30 creation attempts per hour**, whatever their outcome (a
refused attempt counts too), and create at most **30 entities per hour**; beyond, the answer is
`429` with `Retry-After`. Every refused attempt is recorded in the audit log of the instance
(`tenant.provision_refused`, with the reason code only). Reaching `maxTenants` makes the next
creation a `403`; an entity being deleted still counts until its deletion completes. The TLS certificate of the new FQDN is issued by the reverse proxy on the
first request when on-demand TLS is configured; the DNS record of the FQDN is yours to create
beforehand.

## 4. List and follow your entities

`GET /api/v1/provisioning/tenants` lists the entities created by the token, most recent first,
and `GET /api/v1/provisioning/tenants/{tenantId}` returns one of them. Use them to follow the
`setupState` (`setup` then `active`) and `delegatedAdminActivated`.

```bash
curl -sS --fail-with-body -H "Authorization: Bearer ${TT_PROVISIONING_TOKEN}" \
  https://admin.example.com/api/v1/provisioning/tenants

curl -sS --fail-with-body -H "Authorization: Bearer ${TT_PROVISIONING_TOKEN}" \
  https://admin.example.com/api/v1/provisioning/tenants/ten_01JAB00000000000000ENT1TYC
```

```powershell
$auth = @{ Authentication = 'Bearer'; Token = (ConvertTo-SecureString $token -AsPlainText -Force) }
Invoke-RestMethod -Uri 'https://admin.example.com/api/v1/provisioning/tenants' @auth
Invoke-RestMethod -Uri 'https://admin.example.com/api/v1/provisioning/tenants/ten_01JAB00000000000000ENT1TYC' @auth
```

An entity that the token did not create, or that does not exist, answers `404 not-found`
without telling the two apart.

## 5. Errors

Every error is an RFC 9457 Problem with a stable `code`; branch on the status and the `code`
(see [errors.md](errors.md)).

| Status | `code` | Meaning |
|---|---|---|
| 400 | `validation-failed` | Malformed body, unknown field, invalid value. |
| 401 | `unauthenticated` | No `Authorization` header. |
| 401 | `provisioning-token-invalid` | Token malformed, unknown, revoked or expired (also when revoked or expired during the request), or used from outside its IP ranges. The same answer in every case, with the `WWW-Authenticate: Bearer error="invalid_token"` challenge, written to the security log. |
| 403 | `provisioning-scope-exceeded` | Outside the scope of the token. `errors` names the refused field: `/fqdn`, `/storageQuotaBytes`, `/maxTransferBytes`, or an empty pointer when `maxTenants` is reached. |
| 404 | `not-found` | Called on an entity's FQDN, or unknown entity. |
| 409 | `already-exists` | FQDN or delegated admin username already used. |
| 422 | `unknown-background-preset` | The background preset does not exist. |
| 429 | `rate-limited` | More than 30 creation attempts or 30 creations per hour for the token, or an invalid token from an address that already presented ten (`Retry-After` tells when to retry). |
| 503 | `system-smtp-unavailable` | The instance has no system SMTP server, so the activation mail cannot be sent. Nothing is created; ask the operator to configure it. |

Example of a refused FQDN:

```json
{
  "type": "https://github.com/ed-fr/transteira/blob/main/docs/api/errors.md#provisioning-scope-exceeded",
  "title": "Outside the provisioning token scope",
  "status": 403,
  "code": "provisioning-scope-exceeded",
  "errors": [{ "field": "/fqdn", "code": "not-allowed" }]
}
```

Do not retry a `401` in a loop: after ten invalid tokens from one address, the next invalid
tokens from it are answered `429` (and logged) for a while, a valid token still being
accepted; the failures are also counted by the fail2ban and CrowdSec rules of the instance,
which may block the address.

## 6. Certificates for the new tenants

A new entity answers only once its host name has a certificate at the reverse proxy. With Caddy,
use the [`Caddyfile.on-demand`](../../integrations/reverse-proxy/caddy/README.md#on-demand-certificates)
variant: point the DNS of the entities (a wildcard record under your suffix, or one record per
entity) at the proxy, set `TT_TLS_ASK_ALLOWED_IPS` on TransTeira to Caddy's address, and Caddy
obtains the certificate at the first handshake after the entity is created, because TransTeira
confirms that the name is a tenant (`GET /tls/ask`). The endpoint is never reachable from outside.
Mind the ACME rate limits of Let's Encrypt (prefer a wildcard certificate when you can). With
Nginx, Traefik or Apache, use a wildcard certificate (DNS-01 challenge) or add each FQDN by hand.

## 7. What happens next, and who is responsible for what

**The entity starts in setup.** It does not accept deposits yet. TransTeira mails a single-use
activation link to the delegated admin through the system SMTP server. The link is **never
returned** in the API answer and the MSP never sees it. The delegated admin opens it, chooses a
password, configures the two-factor authentication, then goes through the setup assistant
(branding, SMTP, IP ranges, domains, legal texts). When the assistant is completed the entity
becomes `active`. The super admins receive a mail when an entity is created and when its setup
is completed (and the instance-wide webhooks receive the matching events).

**The MSP's responsibilities** (threat model T-272, assumption H15):

- It **chooses the address of the delegated admin** of each entity it creates. Whoever reads
  that mailbox becomes the admin of the entity: check the address with the customer.
- It **protects the token**: a secrets vault or a file readable by the service account only,
  never a Git repository, a ticket or a chat; one token per MSP environment; an expiry date.
- It calls the API from **stable source addresses** declared in the ranges of the token. Any
  other address is refused, which limits what a stolen token can do.
- It tells the super admin when a token must be revoked (departure of an operator, suspected
  leak). Revocation is immediate.

Revoking a token never deletes the entities it created; deleting an entity is done by the super
admin in the administration.
