// Package provisioning implements the provisioning API of TransTeira (V1.2,
// threat model section 6.45): instance-wide provisioning tokens, created and
// revoked by the super admin, with which a service provider creates tenants
// in the setup state, each with its first delegated admin, and follows their
// setup.
//
// A provisioning token is a secret "ttp_" followed by 43 base62 characters
// (256 bits from crypto/rand), shown once and stored as its SHA-256. It is
// parsed, stored and looked up apart from the tenant API tokens of package
// apitoken ("tt_"), which this package never imports: neither kind is ever
// accepted in place of the other (T-269). A token is bound to IP ranges, FQDN
// suffixes and caps (storage quota, transfer limit, number of live tenants);
// every authentication failure answers the same [ErrInvalidToken], whatever
// the cause (T-268), and a token only ever reaches the tenants it created
// (T-270).
package provisioning
