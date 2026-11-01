package provisioning

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestGenerate(t *testing.T) {
	seen := map[string]bool{}
	for range 20 {
		g, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(g.Secret))
		if !ValidSecret(g.Secret) || len(g.Secret) != SecretLen || SecretLen != 47 || g.Prefix != g.Secret[:PrefixLen] ||
			PrefixLen != 8 || !strings.HasPrefix(g.Prefix, "ttp_") || string(g.Hash) != string(sum[:]) {
			t.Fatalf("Generate = %+v", g)
		}
		if seen[g.Secret] {
			t.Fatal("Generate repeated a secret")
		}
		seen[g.Secret] = true
	}
}

func TestGenerateFailure(t *testing.T) {
	old := newSecret
	t.Cleanup(func() { newSecret = old })
	newSecret = func() (string, error) { return "", errBoom }
	if _, err := Generate(); !errors.Is(err, errBoom) {
		t.Errorf("Generate = %v", err)
	}
}

func TestValidSecret(t *testing.T) {
	body := strings.Repeat("A", 43)
	for s, want := range map[string]bool{
		"ttp_" + body:                    true,
		"ttp_" + strings.Repeat("A", 42): false,
		"ttp_" + strings.Repeat("A", 44): false,
		"tt_" + body:                     false, // a tenant API token (T-269)
		"TTP_" + body:                    false,
		"ttp_" + body[:42] + "-":         false,
		"ttp-" + body:                    false,
		"":                               false,
		"Bearer ttp_" + body:             false,
		" ttp_" + body:                   false,
		"ttp_" + body[:42] + "é"[:1]:     false,
	} {
		if got := ValidSecret(s); got != want {
			t.Errorf("ValidSecret(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestContext(t *testing.T) {
	ctx := context.Background()
	if _, ok := FromContext(ctx); ok {
		t.Error("an empty context carries a principal")
	}
	if _, ok := FromContext(NewContext(ctx, Principal{})); ok {
		t.Error("a principal without token is accepted")
	}
	p := Principal{TokenID: "prv_X", Name: "n"}
	got, ok := FromContext(NewContext(ctx, p))
	if !ok || got.TokenID != "prv_X" || got.Name != "n" {
		t.Errorf("FromContext = %+v, %v", got, ok)
	}
}

func TestErrors(t *testing.T) {
	for _, c := range []struct {
		err    error
		target error
	}{
		{&AuthError{Reason: ReasonRevoked}, ErrInvalidToken},
		{&InvalidError{Field: FieldName, Reason: "r"}, ErrInvalid},
		{&ScopeError{Field: FieldFQDN}, ErrScopeExceeded},
		{&ScopeError{Field: FieldMaxTenants}, ErrScopeExceeded},
		{&RateLimitError{RetryAfter: time.Minute}, ErrRateLimited},
	} {
		if !errors.Is(c.err, c.target) || c.err.Error() == "" {
			t.Errorf("%T does not match %v or has no message", c.err, c.target)
		}
		if errors.Is(c.err, errBoom) {
			t.Errorf("%T matches an unrelated error", c.err)
		}
	}
	if (&AuthError{Reason: ReasonIPNotAllowed}).Error() != (&AuthError{Reason: ReasonUnknown}).Error() {
		t.Error("the message of an auth error depends on its reason")
	}
	if !strings.Contains((&ScopeError{Field: FieldMaxTenants}).Error(), "maximum") ||
		!strings.Contains((&ScopeError{Field: FieldFQDN}).Error(), FieldFQDN) {
		t.Error("scope error messages")
	}
}
