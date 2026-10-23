package store

// Depositor is the authenticated sender of a deposit request: the verified
// address of a deposit session, its kind and, for an external depositor,
// its invitation; or an API token. It is the single ownership rule of the
// uploads and the transfers (threat model T-21).
type Depositor struct {
	// Email is the verified address (normalized by Owns before comparing).
	// For an API token, it is the sender address of the request and plays
	// no part in the ownership.
	Email string
	// Kind is the depositor kind.
	Kind DepositorKind
	// InvitationID is the invitation of an external depositor, "" for an
	// internal one.
	InvitationID string
	// APITokenID is the API token of the request ("tok_" + ULID), "" for a
	// deposit session.
	APITokenID string
}

// Owns reports whether d is the sender of t. An API token owns exactly the
// transfers it created, whatever their sender address. A deposit session
// owns the transfers of the same normalized address, the same kind and the
// same invitation ("" for both when internal) that no API token created,
// even with the same address. An address that does not normalize owns
// nothing.
func (d Depositor) Owns(t Transfer) bool {
	if d.APITokenID != "" || t.APITokenID != "" {
		return d.APITokenID == t.APITokenID
	}
	email, err := NormalizeEmail(d.Email)
	if err != nil {
		return false
	}
	return email == t.SenderEmail && d.Kind == t.SenderKind && d.InvitationID == t.InvitationID
}
