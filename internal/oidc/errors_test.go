package oidc

import (
	"errors"
	"testing"
)

func TestErrorText(t *testing.T) {
	t.Parallel()
	if got := (&Error{Reason: ReasonTokenInvalid}).Error(); got != "oidc: token_invalid" {
		t.Errorf("Error() = %q", got)
	}
	e := &Error{Reason: ReasonIssuerError, Stage: StageTLS, Category: CategoryTLS}
	if got := e.Error(); got != "oidc: issuer_error (tls: tls_error)" {
		t.Errorf("Error() = %q", got)
	}
}

func TestReasonOf(t *testing.T) {
	t.Parallel()
	if r := ReasonOf(failure(ReasonStateInvalid)); r != ReasonStateInvalid {
		t.Errorf("ReasonOf(*Error) = %q", r)
	}
	if r := ReasonOf(errors.New("other")); r != ReasonIssuerError {
		t.Errorf("ReasonOf(other) = %q", r)
	}
}

func TestProviderError(t *testing.T) {
	t.Parallel()
	if err := ProviderError(""); err != nil {
		t.Errorf("ProviderError(\"\") = %v", err)
	}
	err := ProviderError("access_denied<script>")
	wantReason(t, err, ReasonIssuerError)
	if err.Error() != "oidc: issuer_error" {
		t.Errorf("remote text reflected: %q", err)
	}
}
