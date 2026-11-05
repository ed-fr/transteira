package apiutil

import (
	"encoding/base64"
	"errors"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/proof"
)

// ProofKeyList renders the public keys of the proofs as the OpenAPI
// ProofKeyList: the raw key in base64url without padding, retiredAt null
// while the key is active. The order of keys is kept.
func ProofKeyList(keys []proof.PublicKey) gen.ProofKeyList {
	out := gen.ProofKeyList{Items: make([]gen.ProofKey, len(keys))}
	for i, k := range keys {
		out.Items[i] = gen.ProofKey{
			KeyId:     k.KeyID,
			Algorithm: gen.Ed25519,
			PublicKey: base64.RawURLEncoding.EncodeToString(k.PublicKey),
			CreatedAt: k.CreatedAt,
		}
		if !k.RetiredAt.IsZero() {
			retired := k.RetiredAt
			out.Items[i].RetiredAt = &retired
		}
	}
	return out
}

// ProofDisposition returns the Content-Disposition of a proof download.
// The name is the ASCII name built by proof.FileName, which holds only
// letters, digits, "_", "-" and one ".", so it needs no quoting.
func ProofDisposition(name string) string {
	return `attachment; filename="` + name + `"`
}

// ProofError maps an error of the proof service to the error the strict
// handler renders: a malformed parameter is a 400 naming it, the rate limit
// a 429 with its Retry-After, a transfer the caller cannot reach a 404
// not-found and a proof that does not exist a 404 proof-not-available.
// Anything else (including the authorization errors of package adminauth,
// which the caller maps) is returned unchanged.
func ProofError(err error) error {
	var (
		invalid *proof.InvalidError
		limited *proof.RateLimitError
	)
	switch {
	case errors.As(err, &invalid):
		return problem.New(problem.CodeValidationFailed,
			problem.WithFieldErrors(problem.FieldError{Field: invalid.Param, Code: "invalid-format"}))
	case errors.As(err, &limited):
		return problem.New(problem.CodeRateLimited, problem.WithRetryAfter(limited.RetryAfter))
	case errors.Is(err, proof.ErrNotFound):
		return problem.New(problem.CodeNotFound)
	case errors.Is(err, proof.ErrNotAvailable):
		return problem.New(problem.CodeProofNotAvailable)
	default:
		return err
	}
}
