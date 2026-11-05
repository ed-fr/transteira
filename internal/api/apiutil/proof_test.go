package apiutil

import (
	"errors"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/api/gen"
	"github.com/ed-fr/transteira/internal/api/problem"
	"github.com/ed-fr/transteira/internal/proof"
)

func TestProofKeyList(t *testing.T) {
	if got := ProofKeyList(nil); got.Items == nil || len(got.Items) != 0 {
		t.Errorf("nil = %#v, want an empty list", got)
	}
	created := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	pub := make([]byte, 32)
	pub[0], pub[31] = 0xfb, 0xff // "-" and "_" in base64url, no padding
	got := ProofKeyList([]proof.PublicKey{
		{KeyID: "psk_2", PublicKey: pub, CreatedAt: created.Add(time.Hour)},
		{KeyID: "psk_1", PublicKey: pub, CreatedAt: created, RetiredAt: created.Add(time.Hour)},
	})
	if len(got.Items) != 2 || got.Items[0].KeyId != "psk_2" || got.Items[0].RetiredAt != nil || got.Items[0].Algorithm != gen.Ed25519 ||
		got.Items[0].PublicKey != "-wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP8" || !got.Items[0].CreatedAt.Equal(created.Add(time.Hour)) ||
		got.Items[1].RetiredAt == nil || !got.Items[1].RetiredAt.Equal(created.Add(time.Hour)) {
		t.Errorf("list = %+v", got)
	}
}

func TestProofDisposition(t *testing.T) {
	if got, want := ProofDisposition("transteira-proof-deposit-trf_x.pdf"), `attachment; filename="transteira-proof-deposit-trf_x.pdf"`; got != want {
		t.Errorf("ProofDisposition = %q, want %q", got, want)
	}
}

func TestProofError(t *testing.T) {
	boom := errors.New("boom")
	for _, c := range []struct {
		err   error
		code  problem.Code
		field string
		retry int
	}{
		{&proof.InvalidError{Param: proof.ParamKind}, problem.CodeValidationFailed, "kind", 0},
		{&proof.RateLimitError{RetryAfter: 1500 * time.Millisecond}, problem.CodeRateLimited, "", 2},
		{proof.ErrNotFound, problem.CodeNotFound, "", 0},
		{proof.ErrNotAvailable, problem.CodeProofNotAvailable, "", 0},
	} {
		var p *problem.Problem
		if err := ProofError(c.err); !errors.As(err, &p) || p.Code != c.code {
			t.Fatalf("%v: %v, want %s", c.err, err, c.code)
		}
		if c.field != "" && (len(p.Errors) != 1 || p.Errors[0].Field != c.field || p.Errors[0].Code != "invalid-format") {
			t.Errorf("%v: errors = %+v", c.err, p.Errors)
		}
		if c.retry != 0 && (p.RetryAfterSeconds == nil || *p.RetryAfterSeconds != c.retry) {
			t.Errorf("%v: retry = %v", c.err, p.RetryAfterSeconds)
		}
	}
	if err := ProofError(boom); !errors.Is(err, boom) {
		t.Errorf("unknown error = %v", err)
	}
}
