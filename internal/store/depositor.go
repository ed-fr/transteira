package store

// Depositor is the authenticated sender of a deposit request: the verified
// address of a deposit session, its kind and, for an external depositor,
// its invitation. It is the single ownership rule of the uploads and the
// transfers (threat model T-21).
type Depositor struct {
	// Email is the verified address (normalized by Owns before comparing).
	Email string
	// Kind is the depositor kind.
	Kind DepositorKind
	// InvitationID is the invitation of an external depositor, "" for an
	// internal one.
	InvitationID string
}

// Owns reports whether d is the sender of t: the same normalized address,
// the same kind and the same invitation ("" for both when internal). An
// address that does not normalize owns nothing.
func (d Depositor) Owns(t Transfer) bool {
	email, err := NormalizeEmail(d.Email)
	if err != nil {
		return false
	}
	return email == t.SenderEmail && d.Kind == t.SenderKind && d.InvitationID == t.InvitationID
}
