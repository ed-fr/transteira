# Administration

This page covers the admin host, the first-run setup, admin accounts, the
second factor and how to recover access.

- Variables: `TT_ADMIN_HOSTS` (required), `TT_ADMIN_SESSION_IDLE_TIMEOUT`,
  `TT_ADMIN_SESSION_MAX_AGE`, `TT_SETUP_TOKEN` / `TT_SETUP_TOKEN_FILE`, see
  `.env.example`.
- Commands: `transteira admin list`, `transteira admin reset-totp <username>`,
  `transteira admin reset-password <username>`.
- Implementation: `internal/adminauth`, `internal/audit`,
  `internal/api/admin`.
- Threat model: T-58 to T-67, T-102 in `docs/security/threat-model.md`.

## Admin host

The administration is served **only** on the host names listed in
`TT_ADMIN_HOSTS`, for example `admin.transfer.example.com`. It never answers
on a tenant FQDN (admin routes return 404 there), and the public deposit and
download pages never answer on the admin host. An admin host must not be a
tenant FQDN: TransTeira refuses to start if it is.

Configure the admin host in the reverse proxy like a tenant host (TLS
certificate, real client IP). You can restrict it further at the proxy, for
example to your internal networks or a VPN.

## First-run setup

While no admin exists, the setup creates the **super admin**. The web
pages arrive with the web interface; until then, the same steps are
available through the API (`/api/v1/admin/setup`, then
`/api/v1/admin/me/totp/confirm`, see `docs/api/`).

1. Open `https://<admin host>/admin/setup`.
2. Enter the setup token:
   - if `TT_SETUP_TOKEN` (or `TT_SETUP_TOKEN_FILE`) is set, use that value;
   - otherwise TransTeira generates a random token at each start and prints
     it once in the container logs (`docker logs transteira`). It is valid
     until the next restart.
3. Choose a username, an email address and a password (12 to 1024
   characters, no other rule).
4. Scan the QR code with an authenticator app (TOTP) and confirm with a
   code. **TOTP is mandatory for the super admin**: nothing else in the
   administration is usable before it is confirmed.
5. Write down the 8 recovery codes shown once, and keep them in your
   password vault.

Once an admin exists, the setup is closed for good and no token is printed
any more.

## Sessions

- Opaque server-side session in the `__Host-tt_admin` cookie (`Secure`,
  `HttpOnly`, `SameSite=Strict`), rotated after each authentication step.
- Expires after `TT_ADMIN_SESSION_IDLE_TIMEOUT` of inactivity (30 min by
  default) and at the latest after `TT_ADMIN_SESSION_MAX_AGE` (12 h).
- An intermediate step (password accepted, second factor or enrollment
  pending) expires after 5 minutes.
- Every state-changing request needs the CSRF token returned by the API and
  a same-origin request.

## Brute-force protection

- 5 failed logins for one username from one IP within 15 minutes lock that
  pair for 15 minutes; 20 failures from one IP lock the IP. There is no lock
  on a username alone, so nobody can lock the super admin out from
  elsewhere.
- Wrong second factors, including wrong TOTP enrollment confirmation
  codes, are counted per account as well (5 within 15 minutes lock the
  second factor for 15 minutes); only someone holding the password or a
  session can reach that lock.
- Every failure is written to the security log (`admin_login_failed`) and
  every lock as `rate_limited`, for fail2ban and CrowdSec
  (see [Security log](security-log.md)).

## Delegated admins

The super admin creates delegated admins and assigns them to one or more
tenants. The response contains an **activation link, shown once**: give it
to the new admin yourself, through a channel you trust (in person, your
messaging tool). TransTeira never mails it: a tenant's SMTP settings are
managed by that tenant's delegated admins, who could otherwise capture the
link of an account that also manages other tenants (threat model T-143).
The link is valid for 72 hours and works once; the token is in the URL
fragment, so it never reaches the server logs. The admin chooses a
password, then enrolls TOTP when it is required (the default).

A delegated admin only sees and manages their own tenants. Disabling an
account, changing its tenants or its role, or resetting its credentials
revokes its sessions and cancels a pending activation link. A delegated
admin can be promoted to super admin only once activated with TOTP
enrolled. The last usable super admin (password set, TOTP enrolled, not
disabled) cannot be deleted, disabled or demoted, and nobody can delete,
disable, demote or reset their own account. Keeping two super admins is
recommended.

## Changing the second factor

Enrolling or replacing TOTP from an authenticated session requires the
current password. Replacing an active TOTP (new phone) also revokes the
other sessions of the account; the new enrollment issues 8 new recovery
codes. A stolen session alone therefore cannot take over the second
factor. The new secret must be confirmed within 15 minutes, and wrong
confirmation codes count as wrong second factors (see above).

## Losing the second factor

In this order:

1. **Recovery code**: at the second-factor step, enter one of the 8 recovery
   codes instead of the TOTP code. Each code works once. The codes are
   stored as an HMAC keyed from the (sealed) TOTP secret, so a stolen
   database alone cannot be used to test them, and they remain valid
   across a master key rotation. Confirming a new
   TOTP enrollment issues 8 new codes and invalidates the old ones.
2. **Another super admin** can reset the credentials of any other admin
   (`reset-credentials`): password and TOTP are cleared, sessions revoked,
   and a new activation link is shown once, to be transmitted out of
   band.
3. **Local command**, when no other way is left (for example the only super
   admin lost both the TOTP device and the recovery codes). It must be run
   inside the container, so it requires access to the host:

   ```sh
   docker exec -it transteira transteira admin list
   docker exec -it transteira transteira admin reset-totp superadmin
   ```

   It clears the TOTP secret and the recovery codes of that account and
   revokes its sessions; the admin enrolls a new TOTP at the next login
   (the password is unchanged). The action is written to the audit log.
   Anyone who knows the password can enroll in the meantime: if the
   password may be compromised too, use `reset-password` instead.

## Losing the password

Another super admin resets the account as above. If you are the only super
admin, run inside the container:

```sh
docker exec -it transteira transteira admin reset-password superadmin
```

It clears the password, the TOTP and the recovery codes, revokes the
sessions and prints an activation link valid 72 hours, once. Open it to
choose a new password and enroll TOTP again. The action is written to the
audit log.

## Audit log

Admin actions are written to the audit log: logins (successful or not),
setup, TOTP enrollment and removal, recovery code use, password changes,
creation, update, deletion, activation and reset of accounts, and local
resets. Entries are kept 12 months, then purged by the cleanup task. There
is no way to edit or delete them through the application.
