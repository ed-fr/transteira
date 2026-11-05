// Package oidc is the OpenID Connect relying party of the administrators'
// single sign-on (since 2.0, threat model §6.48, T-286 to T-297).
//
// It is a library without database access: the admin authentication
// service reads the single sign-on configuration of a tenant, hands it to
// this package and acts on the result. The package provides:
//
//   - [CheckIssuer] and [IsEntraTenantIssuer], the rules on the issuer URL
//     (https only, Microsoft Entra ID multi-tenant issuers refused, T-288);
//   - [Client], a hardened HTTP client (egress guard on every connection,
//     TLS 1.2 or later verified, no redirect followed, bodies capped at
//     64 KiB, proxy ignored unless enabled, T-295) with a cache of the
//     validated discovery documents and of the signing keys of each issuer
//     (unknown key ID: at most one key reload per minute, T-290);
//   - [Client.Test], the discovery test of the administration, whose result
//     only ever holds closed categories, never a remote text;
//   - [Flows], the pending authorization code flows (PKCE S256, state and
//     nonce of 256 bits each, kept in memory, single use, 10 minutes,
//     bound to the browser by a MAC-signed cookie, T-289);
//   - [Flows.Redeem], the code exchange and the ID token validation
//     (algorithms RS256, PS256 and ES256 only, exact issuer, audience and
//     authorized party, expiry, issue and not-before times with a leeway of
//     2 minutes, nonce), returning an [Identity].
//
// Every failure is an [*Error] carrying a closed reason, one of the
// securitylog reasons of the sso_failed event: its text never holds a
// message of the network, of the identity provider or of a library.
package oidc
