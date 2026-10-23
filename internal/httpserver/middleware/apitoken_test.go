package middleware

import (
	"context"
	"testing"
)

func TestAPITokenContext(t *testing.T) {
	t.Parallel()
	if _, ok := APITokenFrom(context.Background()); ok {
		t.Error("a token principal in an empty context")
	}
	want := TokenPrincipal{TokenID: "tok_01JAAAAAAAAAAAAAAAAAAAAAAA", Name: "nightly export"}
	got, ok := APITokenFrom(WithAPIToken(context.Background(), want))
	if !ok || got != want {
		t.Errorf("APITokenFrom = %+v, %v, want %+v", got, ok, want)
	}
}
