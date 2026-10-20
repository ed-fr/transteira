package tenant

import (
	"errors"
	"fmt"

	"github.com/ed-fr/transteira/internal/id"
)

// ErrInvalidID reports a malformed tenant identifier.
var ErrInvalidID = errors.New("tenant: invalid tenant id")

// ID identifies a tenant. Its textual form is "ten_" followed by a 26
// character ULID in upper-case Crockford base32, matching the pattern
// ^ten_[0-9A-HJKMNP-TV-Z]{26}$ of the OpenAPI specification (validated by
// [id.Valid]).
//
// Code serving a request obtains an ID only from the request context
// ([IDFromContext]); administration code obtains it after checking the
// admin's scope.
type ID string

// ParseID validates s and returns it as an ID.
func ParseID(s string) (ID, error) {
	tid := ID(s)
	if err := tid.Validate(); err != nil {
		return "", err
	}
	return tid, nil
}

// Validate reports whether the identifier is a well-formed tenant ID.
func (tid ID) Validate() error {
	if !id.Valid(id.Tenant, string(tid)) {
		return fmt.Errorf("%w: %q", ErrInvalidID, truncate(string(tid)))
	}
	return nil
}

// String returns the textual form of the identifier.
func (tid ID) String() string { return string(tid) }

// IsZero reports whether the identifier is empty.
func (tid ID) IsZero() bool { return tid == "" }
