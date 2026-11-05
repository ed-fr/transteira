# Single sign-on (OpenID Connect)

Since 2.0, delegated admins and auditors of an entity can sign in to the
administration with the identity provider of their organization (Microsoft
Entra ID, Keycloak, any OpenID Connect provider) instead of a local password
and TOTP. The provider is configured **per entity**, by the **super admin**
only. Single sign-on is for the **administration interface only**: API
tokens, deposit links and the public pages are unchanged
([API guide](../api/integration.md)).

Français : [docs/operations/fr/sso.md](fr/sso.md).

- Variables: `TT_SSO_USE_PROXY`, `TT_SSO_ALLOW_NETWORKS`, see `.env.example`.
  Everything else (issuer, client ID, client secret, domains, options) is
  stored per entity and managed in the administration.
- Operations: `getTenantSso`, `putTenantSso`, `deleteTenantSso`,
  `testTenantSso`, `startAdminOidcLogin`, `completeAdminOidcLogin`,
  `getAdminAuthMethods`, `deleteAdminIdentity` (`api/openapi.yaml`).
- Threat model: T-286 to T-297 (section 6.48), decisions P57 to P59 in
  `docs/security/threat-model.md`.

## How it works

- **Flow:** authorization code with PKCE (S256), `state` and `nonce`;
  TransTeira is a **confidential client** (client secret sent to the token
  endpoint over verified TLS). The flow context lives in a signed technical
  cookie of the admin host, valid 10 minutes and usable once.
- **Redirect URI** to register at the provider, on **the admin host**
  (`TT_ADMIN_HOSTS`):

  ```text
  https://admin.example.com/api/v1/admin/auth/oidc/callback
  ```

- **The super admin never uses single sign-on.** The local account with
  password and TOTP stays available whatever the configuration: it is the
  way to fix or disable the single sign-on of an entity.
- **Accounts are created in advance** by the super admin. Nobody is created
  by a login. An unknown account, an account of another entity or a disabled
  one is refused.
- **The second factor is delegated to the provider** (`requireMfa`, on by
  default): the login is accepted only if the ID token proves that multi-factor
  authentication was done (`amr` containing `mfa`).
- **Session scope.** An SSO session reaches only the entities of the account
  whose single sign-on configuration is enabled **with the same issuer and
  client ID** as the login, and whose `requireMfa` that login satisfied. Any
  other entity of the account answers `404 not-found` to that session.
  Signing in again with the local password gives access to the entities that
  do not enforce single sign-on.

## Microsoft Entra ID

### 1. Register the application

In the Entra admin center (or Azure portal) of the organization's directory:

1. **App registrations > New registration**. Name: for example
   `TransTeira entity A`. Supported account types: **Accounts in this
   organizational directory only (single tenant)**.
2. **Redirect URI**: platform **Web**, value
   `https://admin.example.com/api/v1/admin/auth/oidc/callback` (your admin
   host). Register it exactly, with no trailing slash.
3. From the **Overview** page, note the **Application (client) ID** and the
   **Directory (tenant) ID**.
4. **Certificates & secrets > New client secret**: copy the **Value** (shown
   once) and note its expiry date: the secret must be renewed in TransTeira
   before it (see [Renewing the secret](#renewing-the-secret)).
5. **API permissions**: the default delegated `User.Read` is enough. TransTeira
   asks for the scopes `openid`, `profile` and `email` only.

### 2. Issuer: tenant-specific, never `common`

The issuer to enter in TransTeira is:

```text
https://login.microsoftonline.com/<directory-tenant-id>/v2.0
```

TransTeira **refuses** the multi-tenant endpoints `common`, `organizations`
and `consumers` (`422 sso-issuer-not-allowed`): they accept users of any
Entra directory, and a token could then be issued for a foreign directory.

### 3. Add the `amr` optional claim (required for `requireMfa`)

Entra ID **v2 ID tokens carry the `amr` claim only if it is requested** as an
optional claim. Without it, TransTeira never sees `mfa` and every login fails
with `sso-mfa-required` (reason `mfa_missing` in the security log).

1. In the application: **Token configuration > Add optional claim**.
2. Token type **ID**, claim **`amr`**, then **Add** (accept the prompt to turn
   on the Microsoft Graph permission if shown).

Equivalent in the **Manifest**:

```json
"optionalClaims": {
  "idToken": [
    { "name": "amr", "source": null, "essential": false, "additionalProperties": [] }
  ]
}
```

### 4. Require MFA with Conditional Access

The `amr` claim only **reports** what happened; it is Entra that must **do**
the multi-factor authentication. Create a **Conditional Access** policy:

- **Target resources:** the TransTeira application (select it by name).
- **Users:** the delegated admins and auditors (a group is convenient).
- **Grant:** *Require multifactor authentication* (or an authentication
  strength).

A user who signs in with a valid session that already satisfied MFA gets
`mfa` in `amr` without a new prompt; this is expected.

### 5. What Entra sends and how the account is matched

TransTeira matches the account on the first login by a **verified e-mail
address**: the `email` claim with `email_verified: true`, or, for a
tenant-specific Entra issuer, `preferred_username` (the user principal name,
which Entra guarantees unique in the directory). Entra does not always
include `email_verified` or `email`, which is why `preferred_username` is
accepted for this kind of issuer. The address must match the e-mail address of
the pre-created account, and its domain must be one of the SSO domains of the
entity.

## Generic provider (Keycloak and others)

Any provider that supports OpenID Connect discovery
(`<issuer>/.well-known/openid-configuration`), the authorization code flow with
PKCE S256 and signed ID tokens (RS256, PS256 or ES256) works. Example with
Keycloak (realm `corp`):

1. **Clients > Create client**: type **OpenID Connect**, client ID
   `transteira-entity-a`, **Client authentication: On** (confidential),
   **Standard flow** only (disable direct access grants and implicit flow).
2. **Valid redirect URIs**:
   `https://admin.example.com/api/v1/admin/auth/oidc/callback`.
   **Advanced > Proof Key for Code Exchange Code Challenge Method:** `S256`.
3. **Credentials**: copy the **Client secret**.
4. Issuer: `https://sso.example.com/realms/corp`. It must be exactly the
   `issuer` of the discovery document.
5. Make sure the users have a verified e-mail address (`email` and
   `email_verified: true`): on the first login TransTeira accepts the token but the first login fails (`account_unknown`).
6. For `requireMfa`, the token must carry `amr` containing `mfa`. In Keycloak,
   add an **Authentication Method Reference** mapper to the client (or require
   a two-factor flow) so that `amr` is issued; if your provider cannot assert
   `amr`, turn `requireMfa` off for this entity and enforce MFA at the
   provider, knowing that TransTeira then cannot check it.

The provider must be reachable over **HTTPS** from the TransTeira container. A
provider on a private network needs
[`TT_SSO_ALLOW_NETWORKS`](#private-networks-and-proxy).

## Configuring an entity in TransTeira

Reserved to the **super admin**. Delegated admins and auditors can read the
configuration (the secret is never returned: `hasClientSecret` only).

In the administration, open the entity, then **Single sign-on**. Fields:

| Field | Meaning |
|---|---|
| Enable single sign-on | Turns the login on or off for the entity. |
| Issuer | `https` URL of the provider. Entra: tenant-specific (see above). |
| Client ID | Application (client) ID. |
| Client secret | Write-only. Required the first time and whenever the issuer or the client ID changes; otherwise leave empty to keep the stored one. Sealed with the master key like the SMTP password, and covered by the [master key rotation](master-key.md). |
| E-mail domains | Domains routed to this entity's provider. Each must be one of the entity's **internal mail domains**, and belongs to **one entity** on the whole instance (`409 sso-domain-conflict` otherwise). |
| Enforce single sign-on (`enforced`) | Refuses the local password login for delegated admins and auditors attached to the entity. Off by default. |
| Require MFA (`requireMfa`) | The ID token must prove multi-factor authentication. On by default. |

Use **Test** before enabling: TransTeira fetches the discovery document of the
issuer and checks it names the same issuer and the needed endpoints. The test
signs nobody in and never sends the client secret; its failures are reported by
category (`dns_error`, `connect_error`, `tls_error`, `timeout`, `http_status`,
`invalid_document`, `issuer_mismatch`, `missing_endpoint`).

Through the API (super admin session, CSRF token):

```sh
curl -sS -X PUT https://admin.example.com/api/v1/admin/tenants/$TENANT_ID/sso \
  -H "Cookie: $SESSION_COOKIE" -H "X-CSRF-Token: $CSRF" \
  -H 'Content-Type: application/json' \
  -d '{
    "enabled": true,
    "issuer": "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
    "clientId": "7f3c9a10-0000-4000-8000-00000000c0de",
    "clientSecret": "client-secret-from-the-provider",
    "emailDomains": ["entity-a.example.com"],
    "enforced": false,
    "requireMfa": true
  }'
```

Every change is audited as `tenant.sso_updated` (names of the changed members,
never the secret); removal as `tenant.sso_deleted`.

### Changing or removing the configuration

- **Changing the issuer or the client ID** **revokes the SSO sessions** of the
  entity and **unpins the identities** pinned for the former (issuer, client
  ID), unless another entity of the same account still uses that pair. A new
  client secret is then required: a stored secret is never carried over to
  another application.
- **Disabling or deleting** the configuration **revokes the SSO sessions** of
  the entity but **keeps the pinned identities**. They are unusable until a
  configuration with the same (issuer, client ID) pair returns, and then work
  again without a new first login.
- Accounts created without activation link (SSO-only) cannot sign in until the
  configuration is back.

### Renewing the secret

Create a second secret at the provider, then **PUT** the configuration with the
new `clientSecret` (same issuer and client ID), then delete the old secret at
the provider. A secret that expired makes every login fail at the token
exchange (`issuer_error`).

## Accounts

### SSO-only accounts

When creating a delegated admin or an auditor, the super admin can choose the
delivery **`none`** (**Single sign-on only, no activation link**): the account has **no password** and
can sign in only through single sign-on. It requires that **every entity of the
account has its single sign-on enabled** (`409 sso-not-configured` otherwise).
Never possible for a super admin. The list of administrators shows these
accounts as SSO-only (`ssoOnly`).

The other deliveries (`mail`, `copy`) create a normal account that can use both
ways, unless `enforced` is on.

### First login and pinning

1. The person enters their e-mail address on the sign-in page; if its domain is
   routed to an entity with single sign-on, the page offers **Sign in with
   single sign-on** (`POST /admin/auth/oidc/start`, then the redirect to the
   provider). A domain without single sign-on gets `404 sso-not-available`,
   identical to an unknown domain.
2. At the provider, the person authenticates (MFA if required).
3. On the **first** login, TransTeira matches the account by the verified
   e-mail address (see above) and **pins the identity** on
   (issuer, client ID, subject): audit `admin.identity_linked`.
4. On every later login, only that triple counts. The address is no longer
   used, so a renamed mailbox keeps working (changing the e-mail address of an
   account in TransTeira, however, **unpins** its identities), and **another subject presenting
   the same address is refused** (`identity_mismatch`). In Entra ID the `sub`
   is specific to each application: the same person has a different subject in
   another app registration, hence the client ID in the key.
5. The role is checked at **every** login: an account promoted to super admin
   can no longer sign in through single sign-on (its pinned identities are
   removed).
6. Multi-factor authentication for a single sign-on login is governed by the
   **`requireMfa`** setting of the entity. The local "TOTP required" setting of
   the account does not apply to it.

### Unpinning an identity

When a person changes provider account (new directory, new user object), the
super admin removes the pinned identity: **Administrators**, **Edit** on the account,
**Pinned single sign-on identities**, **Unpin** (`DELETE /admin/admins/{adminId}/identities/{identityId}`,
audit `admin.identity_unlinked`, reason `unpinned`). Unpinning also **revokes the
sessions opened through that identity**. At the next login the account is pinned again
to the identity that matches its e-mail address. Do it only after checking
that the new identity belongs to the same person.

## Enforced mode and outage procedure

With **`enforced`** on, the local password login of a delegated admin or an
auditor attached to the entity is refused with `403 sso-required`, **after** the
password check and at the same cost, so that the answer does not reveal whether
the account exists. Recommended once everyone has signed in with single sign-on
at least once.

In addition, an existing **password session** (opened through an activation
link, or before enforcement was switched on) no longer reaches the enforced
entities: they disappear from the account's entity list until the person signs
in through single sign-on. The super admin is never affected.

An account attached to **several** entities is refused the local password as
soon as **one** of them enforces single sign-on.

**If the provider is down** (outage, expired client secret, deleted
application) and the administrators are locked out:

1. The **super admin** signs in locally (password and TOTP: this account never
   depends on single sign-on).
2. Open the entity, **Single sign-on**, untick **Enforce single sign-on**, save
   (audit `tenant.sso_updated`). Delegated admins with a password can sign in
   locally again at once.
3. SSO-only accounts (`delivery: none`) have no password and cannot sign in
   until the provider is back.
4. Fix the provider (renew the secret, restore the application), run the
   **Test**, then enable `enforced` again.

Keep the super admin credentials and recovery codes accessible outside the
provider: they are the fallback (see [Administration](admin.md)).

## Proxy and private networks

The OpenID Connect client uses the same egress guard as the webhooks
(`internal/netpolicy`): HTTPS only, the address is checked **at connection
time** after a fresh resolution (no DNS rebinding), no redirect followed,
short timeout and bounded bodies.

- **`TT_SSO_USE_PROXY`** (default `false`). By default the client ignores
  `HTTPS_PROXY` and connects directly. With `true`, it goes through the proxy
  of the container: the guard then sees **only the proxy**, and the proxy
  resolves and reaches the provider itself. Enable it only if the container has
  no direct Internet access, and restrict the destinations at the proxy.
- **`TT_SSO_ALLOW_NETWORKS`** (default empty). The built-in deny list refuses
  private ranges (RFC 1918, `100.64.0.0/10`, `fc00::/7` ...). To use an
  **on-premises** provider (ADFS, Keycloak) on a private network, list its
  address or the narrowest prefix, for example
  `TT_SSO_ALLOW_NETWORKS=10.20.30.0/28`. The core of the deny list (unspecified,
  link-local and cloud metadata addresses, multicast, reserved ranges, the
  networks of the container) can never be opened; such a prefix stops
  TransTeira at startup. Restart after changing it.

Both apply to the discovery document, the signing keys and the token endpoint.
The browser is redirected to the `authorization_endpoint`, which is only
checked to be an `https` URL without credentials.

## Troubleshooting

The login page shows a generic message for most failures, on purpose; the
reason is in the [security log](security-log.md) (event `sso_failed`, field
`reason`) and the application log.

| Page error code | Security log `reason` | Cause and fix |
|---|---|---|
| `sso-mfa-required` | `mfa_missing` | The ID token has no `amr` containing `mfa`. Entra: add the optional claim `amr` to the ID token and require MFA by Conditional Access; or turn `requireMfa` off knowingly. |
| `sso-not-available` | none | The domain has no enabled single sign-on, or is unknown (same answer on purpose). Check the entity's SSO domains and that it is enabled. |
| `invalid-credentials` | `state_invalid` | Flow cookie missing, expired (10 minutes) or already used; stale tab, bookmarked callback, restart of TransTeira during the login. Start again from the sign-in page. |
| `invalid-credentials` | `token_invalid` | The ID token or the code exchange failed: wrong client secret (expired?), wrong client ID, wrong redirect URI, signature, `nonce`, audience or expiry, or a token of another Entra directory (`tid` not matching the issuer). Run **Test**; check the redirect URI is exactly the one above. |
| `invalid-credentials` | `account_unknown` | No account of this entity matches (not created, e-mail address not verified by the provider (the token is accepted but the first login fails), Entra B2B guest user (the `idp` claim differs from the issuer: refused for the first linking), disabled, super admin, other entity, address outside the SSO domains, or Entra without `preferred_username`). Create the account first. |
| `invalid-credentials` | `identity_mismatch` | The account is pinned to another subject. Verify the person, then **unpin** the old identity. |
| `invalid-credentials` | `issuer_error` | The provider could not be reached or its documents are wrong: DNS, TLS, private network not opened (`TT_SSO_ALLOW_NETWORKS`), proxy, issuer different from the discovery document. |
| `rate-limited` | (`rate_limited`) | Too many attempts from this address; wait. |
| API `403 sso-required` | none | Local password refused: the entity enforces single sign-on. |
| API `422 sso-issuer-not-allowed` | none | Not `https`, or `common`, `organizations`, `consumers`. |
| API `409 sso-domain-conflict` | none | The domain is already routed to another entity. |
| API `409 sso-not-configured` | none | `delivery: none` while one entity of the account has no enabled single sign-on. |
| API `400 validation-failed` (`not-internal-domain`) | none | An SSO domain is not among the entity's internal mail domains (`/emailDomains/<n>`). |

Error codes are described in the [error catalogue](../api/errors.md).

## Security notes

- **Who decides who signs in is the provider of the entity**, configured by the
  super admin only: a delegated admin cannot choose an issuer. A compromised
  provider, or an administrator of the Entra directory, can issue tokens for
  any pinned account of the entity and assert MFA: this is an accepted trust
  (threat model H16). Limit who administers the app registration and keep
  Conditional Access in place.
- Accounts are never created by a login; roles are checked at every login;
  the super admin never uses single sign-on.
- The client secret is sealed with the master key, never returned by the API,
  never written to the logs, the audit or the configuration export.
- Failed logins are written to the security log (`sso_failed`) and counted by a
  separate fail2ban jail and CrowdSec scenario with a **higher threshold** than
  password failures, since a stale tab causes `state_invalid`
  ([fail2ban](../../integrations/fail2ban/README.md),
  [CrowdSec](../../integrations/crowdsec/README.md)).
- Audit actions: `admin.login` (`details.method` = `oidc`),
  `admin.identity_linked`, `admin.identity_unlinked`, `tenant.sso_updated`,
  `tenant.sso_deleted`.
- The OpenID Connect client accepts only RS256, PS256 and ES256 signatures,
  reads the keys from the issuer's `jwks_uri` under the egress guard, and
  checks issuer, audience, `nonce`, `exp`, `iat` and `nbf` (2 minutes of
  tolerance). On Entra, a token whose `tid` does not match the issuer is
  refused, and a B2B guest user (`idp` claim different from the issuer) cannot
  be linked at the first login.
- `admin.identity_unlinked` carries `identity_id`, `issuer`, `client_id` and
  `reason`: `unpinned` (manual), `promoted` (account promoted to super admin),
  `sso_changed` (issuer or client ID changed), `email_changed` (e-mail address
  of the account changed).
- A callback request without a valid flow cookie (for example a cross-site
  request) gets the generic error but is neither counted nor logged, so a
  third-party page cannot get an administrator banned. Starting single sign-on
  for an unavailable domain counts on the per-IP admin login limit (20
  failures per 15 minutes), which limits domain probing.
