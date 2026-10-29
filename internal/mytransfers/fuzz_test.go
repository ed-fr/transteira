package mytransfers

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/store/storetest"
)

// linkTokenRe is the pattern of an access link token in the OpenAPI
// document (MyTransfersSessionStart.token).
var linkTokenRe = regexp.MustCompile(`^mta_[A-Za-z0-9]{22,43}$`)

// FuzzStartSessionToken checks that StartSession never panics, answers
// ErrAccessLinkInvalid for every token it does not find, and never looks a
// token up in the store unless it has the shape of the specification.
func FuzzStartSessionToken(f *testing.F) {
	for _, s := range []string{
		"", "mta_", "mta_" + strings.Repeat("a", 22), "mta_" + strings.Repeat("Z", 43), "mta_" + strings.Repeat("9", 44),
		"MTA_" + strings.Repeat("a", 22), "mta_" + strings.Repeat("a", 21) + "-", "ms_" + strings.Repeat("a", 43),
		"mta_" + strings.Repeat("a", 22) + "\x00", "mta_ÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄÄ",
	} {
		f.Add(s)
	}
	ev := newEnv(f, storetest.SQLite(f))
	ev.svc.failures = &fakeFailures{}
	f.Fuzz(func(t *testing.T, token string) {
		ev.repo.reset()
		_, err := ev.svc.StartSession(context.Background(), ev.a, clientIP, token)
		if !errors.Is(err, ErrAccessLinkInvalid) {
			t.Fatalf("StartSession(%q) = %v, want ErrAccessLinkInvalid", token, err)
		}
		looked := len(ev.repo.recorded()) > 0
		if looked != linkTokenRe.MatchString(token) {
			t.Fatalf("StartSession(%q): store looked up = %v, pattern match = %v", token, looked, !looked)
		}
	})
}

// FuzzSessionToken checks that a session cookie of any shape never
// authenticates and never reaches the store unless well formed.
func FuzzSessionToken(f *testing.F) {
	for _, s := range []string{"", "ms_", "ms_" + strings.Repeat("a", 43), "csrf_x", "ds_" + strings.Repeat("a", 43)} {
		f.Add(s, "csrf_"+s)
	}
	ev := newEnv(f, storetest.SQLite(f))
	f.Fuzz(func(t *testing.T, token, header string) {
		ev.repo.reset()
		if _, err := ev.svc.Session(context.Background(), ev.a, token); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("Session(%q) = %v", token, err)
		}
		if len(ev.repo.recorded()) > 0 && !validToken(SessionTokenPrefix, token) {
			t.Fatalf("Session(%q) reached the store", token)
		}
		if ev.svc.CheckCSRF(token, header) {
			t.Fatalf("CheckCSRF(%q, %q) accepted a forged token", token, header)
		}
	})
}

// FuzzListCursor checks that any cursor gives a page or an invalid cursor
// error, never another error.
func FuzzListCursor(f *testing.F) {
	for _, s := range []string{"", "x", "eyJ0IjoxfQ", "AAAA", "%00", strings.Repeat("A", 500)} {
		f.Add(s)
	}
	ev := newEnv(f, storetest.SQLite(f))
	sess := SessionInfo{Email: aliceNorm}
	f.Fuzz(func(t *testing.T, cursor string) {
		_, err := ev.svc.List(context.Background(), ev.a, sess, cursor, 1)
		var ie *InvalidError
		if err != nil && (!errors.As(err, &ie) || ie.Field != FieldCursor) {
			t.Fatalf("List(cursor %q) = %v", cursor, err)
		}
	})
}
