package adminauth

import (
	"fmt"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
)

// Activation is a single-use activation link, valid ActivationTTL. It is
// never mailed: the service returns it once, to the super admin who
// created or reset the account (or to the operator of the local command),
// who hands it to the administrator out of band. Only the SHA-256 of its
// token is stored.
type Activation struct {
	// URL is the link: AdminBaseURL + ActivationPath + "#" + token (the
	// token in the fragment, so that it never reaches a server log or a
	// Referer header).
	URL string
	// ExpiresAt is the end of its validity.
	ExpiresAt time.Time
}

// activationLink returns the activation link of token: the activation page
// of the web interface on the admin host, the token in the fragment.
func (s *Service) activationLink(token string) string {
	return s.baseURL + ActivationPath + "#" + token
}

// newActivation prepares a new activation link of the account adminID at
// now: the row to create (inside the transaction of the account change)
// and the link to return once it is committed.
func (s *Service) newActivation(adminID string, now time.Time) (store.AdminActivation, Activation, error) {
	token, err := s.newToken(ActivationTokenPrefix, tokenBytes)
	if err != nil {
		return store.AdminActivation{}, Activation{}, fmt.Errorf("adminauth: new activation token: %w", err)
	}
	actID, err := s.newID(id.AdminActivation)
	if err != nil {
		return store.AdminActivation{}, Activation{}, fmt.Errorf("adminauth: new activation id: %w", err)
	}
	expires := now.Add(ActivationTTL)
	row := store.AdminActivation{ID: actID, AdminID: adminID, TokenHash: tokenHash(token), CreatedAt: now, ExpiresAt: expires}
	return row, Activation{URL: s.activationLink(token), ExpiresAt: expires}, nil
}
