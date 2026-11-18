package secret

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/tte2"
)

// checkHeaders fails when a request carries a browser header that would
// trigger the cross-site refusal of the server, or the wrong token.
func checkHeaders(t *testing.T, r request, wantToken bool) {
	t.Helper()
	for _, h := range []string{"Origin", "Sec-Fetch-Site", "Referer", "Cookie"} {
		if r.header.Get(h) != "" {
			t.Errorf("%s %s sent %s", r.method, r.path, h)
		}
	}
	auth := r.header.Get("Authorization")
	if wantToken != (auth == "Bearer "+testAPIToken) || (!wantToken && auth != "") {
		t.Errorf("%s %s Authorization %q, want token %v", r.method, r.path, auth, wantToken)
	}
}

func TestCreateAndReadRoundTrip(t *testing.T) {
	f := newFake(t)
	text := "line one\r\nmot de passe : é😀\n"
	for _, tc := range []struct {
		name      string
		token     string
		anonymous bool
		wantToken bool
	}{
		{"anonymous", "", false, false},
		{"token", testAPIToken, false, true},
		{"token forced anonymous", testAPIToken, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := f.client(t, tc.token)
			n := f.count()
			got, err := Create(context.Background(), c, CreateOptions{Text: text, Duration: "1h", Anonymous: tc.anonymous})
			if err != nil {
				t.Fatal(err)
			}
			if f.count() != n+1 {
				t.Fatalf("requests: %d", f.count()-n)
			}
			r := f.last()
			checkHeaders(t, r, tc.wantToken)
			if r.header.Get("Content-Type") != "application/json" {
				t.Errorf("content type %q", r.header.Get("Content-Type"))
			}
			if got.Anonymous == tc.wantToken {
				t.Errorf("anonymous %v", got.Anonymous)
			}
			// Exactly the four members, the duration as given, and nothing
			// of the text or the key in the request.
			var body map[string]any
			if err := json.Unmarshal(r.body, &body); err != nil || len(body) != 4 || body["expiresIn"] != "1h" {
				t.Fatalf("body %s", r.body)
			}
			l, err := ParseLink(got.Link)
			if err != nil {
				t.Fatalf("link does not parse: %v", err)
			}
			if !strings.HasPrefix(got.Link, f.srv.URL+"/s/tts_") || l.Origin != f.srv.URL {
				t.Fatalf("link %q", got.Link)
			}
			if strings.Contains(string(r.body), l.Key) || strings.Contains(string(r.body), "mot de passe") {
				t.Fatal("the key or the text reached the server")
			}
			for name, values := range r.header {
				if strings.Contains(strings.Join(values, " "), l.Key) {
					t.Fatalf("key in header %s", name)
				}
			}
			if got.ExpiresAt.IsZero() || !strings.HasPrefix(got.ID, "sec_") {
				t.Errorf("created %+v", got)
			}
			// The sealed text opens with K' of the link, and both verifiers
			// match the proofs of the link.
			key, err := tte2.DecodeKey(l.Key)
			if err != nil {
				t.Fatal(err)
			}
			m := derive(key)
			opened, err := tte2.OpenSecret(m.root, body["encryptedText"].(string))
			if err != nil || opened != text {
				t.Fatalf("sealed text: %q %v", opened, err)
			}
			v, _ := tte2.ParseProof(body["verifier"].(string))
			kv, _ := tte2.ParseProof(body["keyVerifier"].(string))
			if !tte2.VerifierMatches(v, m.proof) || !tte2.VerifierMatches(kv, m.keyProof) {
				t.Fatal("verifiers do not match the proofs")
			}

			// Read it back once, without token.
			rc := f.client(t, testAPIToken)
			rv, err := Read(context.Background(), rc, l)
			if err != nil {
				t.Fatal(err)
			}
			if rv.Text != text || !rv.Express || rv.Anonymous != !tc.wantToken || rv.FileLost {
				t.Fatalf("revealed %+v", rv)
			}
			checkHeaders(t, f.last(), false)
			if _, err := Read(context.Background(), rc, l); !errors.Is(err, ErrGone) || !strings.Contains(err.Error(), "already read") {
				t.Fatalf("second read: %v", err)
			}
		})
	}
}

func TestCreateEveryKeyIsNew(t *testing.T) {
	f := newFake(t)
	c := f.client(t, "")
	a, err := Create(context.Background(), c, CreateOptions{Text: "x"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Create(context.Background(), c, CreateOptions{Text: "x"})
	if err != nil {
		t.Fatal(err)
	}
	la, _ := ParseLink(a.Link)
	lb, _ := ParseLink(b.Link)
	if la.Key == lb.Key {
		t.Fatal("key reused")
	}
	var body map[string]any
	_ = json.Unmarshal(f.last().body, &body)
	if body["expiresIn"] != DefaultDuration {
		t.Errorf("default duration: %v", body["expiresIn"])
	}
}

func TestCreateRefusedLocally(t *testing.T) {
	f := newFake(t)
	c := f.client(t, "")
	if _, err := Create(context.Background(), c, CreateOptions{Text: "x", Duration: "30d"}); err == nil || !strings.Contains(err.Error(), "1h, 1d or 7d") {
		t.Errorf("duration: %v", err)
	}
	if _, err := Create(context.Background(), c, CreateOptions{Text: ""}); !errors.Is(err, ErrInvalidText) {
		t.Errorf("empty: %v", err)
	}
	if _, err := Create(context.Background(), c, CreateOptions{Text: strings.Repeat("a", MaxTextRunes+1)}); !errors.Is(err, ErrInvalidText) {
		t.Errorf("long: %v", err)
	}

	old := sealSecret
	t.Cleanup(func() { sealSecret = old })
	sealSecret = func([]byte, string) (string, error) { return "", tte2.ErrInvalidSecret }
	if _, err := Create(context.Background(), c, CreateOptions{Text: "x"}); !errors.Is(err, tte2.ErrInvalidSecret) {
		t.Errorf("seal: %v", err)
	}
	// A sealed text that does not open again is never sent.
	sealSecret = func(root []byte, _ string) (string, error) { return old(root, "other") }
	if _, err := Create(context.Background(), c, CreateOptions{Text: "x"}); err == nil || !strings.Contains(err.Error(), "does not open") {
		t.Errorf("self-check: %v", err)
	}
	if f.count() != 0 {
		t.Fatalf("%d requests sent", f.count())
	}
}

func TestCreateProblems(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer problemAnswer
		token  string
		want   error
		text   string
	}{
		{"disabled anonymous", problemAnswer{status: 403, code: codeExpressDisabled}, "", ErrDisabled, "does not accept anonymous"},
		{"disabled with token", problemAnswer{status: 403, code: codeExpressDisabled}, testAPIToken, ErrDisabled, "instance disabled them"},
		{"token not allowed", problemAnswer{status: 403, code: codeTokenNotAllowed}, testAPIToken, ErrTokenNotAllowed, "expressAllowed"},
		{"ip not allowed", problemAnswer{status: 403, code: codeIPNotAllowed}, testAPIToken, ErrTokenRefused, "allowed ranges"},
		{"invalid token", problemAnswer{status: 401, code: "invalid-credentials"}, testAPIToken, ErrTokenRefused, "revoked"},
		{"rate limited", problemAnswer{status: 429, code: "rate-limited", retryAfter: "1200"}, "", ErrRateLimited, "try again in 20m0s"},
		{"rate limited no delay", problemAnswer{status: 429, code: "rate-limited"}, "", ErrRateLimited, "try again later"},
		{"limit reached", problemAnswer{status: 429, code: codeLimitReached}, "", ErrLimitReached, "free up"},
		{"old server", problemAnswer{status: 404, code: "not-found"}, "", ErrNotOffered, "2.3"},
		{"validation", problemAnswer{status: 400, code: codeValidationFailed}, "", ErrRefused, "versions"},
		{"format", problemAnswer{status: 400, code: codeFormatInvalid}, "", ErrRefused, "versions"},
		{"maintenance", problemAnswer{status: 503, code: "maintenance"}, "", nil, "HTTP 503 maintenance"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.setHook(func(int, *http.Request) *problemAnswer { a := tc.answer; return &a })
			_, err := Create(context.Background(), f.client(t, tc.token), CreateOptions{Text: "secret"})
			var p *client.Problem
			if err == nil || !errors.As(err, &p) || !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("error %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("error %v, want %v", err, tc.want)
			}
			if f.count() != 1 {
				t.Fatalf("sent %d times", f.count())
			}
			if strings.Contains(err.Error(), "secret\"") || !strings.Contains(err.Error(), "request req_") {
				t.Errorf("message %q", err)
			}
		})
	}
}

func TestCreateConnectionError(t *testing.T) {
	f := newFake(t)
	c := f.client(t, "")
	f.srv.Close()
	_, err := Create(context.Background(), c, CreateOptions{Text: "x"})
	var re *client.RequestError
	if !errors.As(err, &re) {
		t.Fatalf("error %v", err)
	}
}

func TestCreateInvalidAnswer(t *testing.T) {
	good := func() map[string]any {
		return map[string]any{"id": "sec_01JABCS3T4V5W6X7Y8Z9A0B1C2", "token": "tts_Xp4kQ7mZr2Lw9TfB3nHc8VyJd5Gs1KqA6eWu0RtNb7M", "state": "active", "expiresAt": "2026-11-18T09:00:00Z"} // gitleaks:allow (example token of the specification)
	}
	f := newFake(t)
	c := f.client(t, "")
	f.setCreated(good())
	if _, err := Create(context.Background(), c, CreateOptions{Text: "x"}); err != nil {
		t.Fatalf("good answer: %v", err)
	}
	for _, change := range []func(m map[string]any){
		func(m map[string]any) { m["id"] = "trf_x" },
		func(m map[string]any) { m["token"] = "tts_short" },
		func(m map[string]any) { m["state"] = "pending" },
		func(m map[string]any) { delete(m, "expiresAt") },
	} {
		m := good()
		change(m)
		f.setCreated(m)
		if _, err := Create(context.Background(), c, CreateOptions{Text: "x"}); !errors.Is(err, ErrInvalidAnswer) {
			t.Errorf("answer %v: %v", m, err)
		}
	}
}

func TestReadSecrets(t *testing.T) {
	f := newFake(t)
	c := f.client(t, testAPIToken)
	key := fixedKey(7)

	// A 2.1 link secret without passphrase nor file.
	tok := f.add(key, "v2.1 text", stored{})
	rv, err := Read(context.Background(), c, f.link(tok, key))
	if err != nil || rv.Text != "v2.1 text" || rv.Express || rv.Anonymous {
		t.Fatalf("2.1: %+v %v", rv, err)
	}
	checkHeaders(t, f.last(), false)

	// An express secret created with a token.
	tok = f.add(key, "token text", stored{express: true})
	rv, err = Read(context.Background(), c, f.link(tok, key))
	if err != nil || !rv.Express || rv.Anonymous {
		t.Fatalf("express token: %+v %v", rv, err)
	}
}

func TestReadRefusedBeforeReveal(t *testing.T) {
	f := newFake(t)
	c := f.client(t, "")
	key := fixedKey(1)
	for _, tc := range []struct {
		name string
		s    stored
		want error
		text string
	}{
		{"passphrase", stored{passphrase: true}, ErrUnsupported, "passphrase"},
		{"file", stored{file: true}, ErrUnsupported, "file"},
		{"read", stored{state: "read"}, ErrGone, "already read"},
		{"expired", stored{state: "expired"}, ErrGone, "expired"},
		{"deleted", stored{state: "deleted"}, ErrGone, "deleted"},
		{"locked", stored{state: "locked"}, ErrGone, "locked"},
		{"other reason", stored{state: "strange"}, ErrGone, "it ended"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok := f.add(key, "text", tc.s)
			n := f.count()
			_, err := Read(context.Background(), c, f.link(tok, key))
			if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("error %v", err)
			}
			if f.count() != n+1 || f.last().method != http.MethodGet {
				t.Fatal("a reveal was sent")
			}
			if f.get(tok).state != cmpState(tc.s.state) {
				t.Fatal("state changed")
			}
		})
	}
	// Unknown token.
	tok := f.add(key, "x", stored{})
	f.set(func() { delete(f.secrets, tok) })
	if _, err := Read(context.Background(), c, f.link(tok, key)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("not found: %v", err)
	}
	// Unknown state.
	f.set(func() {
		f.status = map[string]any{"state": "pending", "expiresAt": "2026-11-18T09:00:00Z", "file": nil}
	})
	tok = f.add(key, "x", stored{})
	if _, err := Read(context.Background(), c, f.link(tok, key)); !errors.Is(err, ErrInvalidAnswer) {
		t.Fatalf("state: %v", err)
	}
}

// cmpState returns the stored state of a secret added with state s.
func cmpState(s string) string {
	if s == "" {
		return "active"
	}
	return s
}

func TestReadExpressClosed(t *testing.T) {
	f := newFake(t)
	c := f.client(t, "")
	key := fixedKey(2)
	tok := f.add(key, "text", stored{express: true, anonymous: true})
	f.setHook(func(int, *http.Request) *problemAnswer { return &problemAnswer{status: 403, code: codeExpressDisabled} })
	_, err := Read(context.Background(), c, f.link(tok, key))
	if !errors.Is(err, ErrDisabled) || !strings.Contains(err.Error(), "nothing was consumed") || f.count() != 1 {
		t.Fatalf("status closed: %v (%d requests)", err, f.count())
	}
	// Closed between the status and the reveal.
	f.setHook(func(_ int, r *http.Request) *problemAnswer {
		if r.Method == http.MethodPost {
			return &problemAnswer{status: 403, code: codeExpressDisabled}
		}
		return nil
	})
	if _, err := Read(context.Background(), c, f.link(tok, key)); !errors.Is(err, ErrDisabled) {
		t.Fatalf("reveal closed: %v", err)
	}
	// Reopened: the secret was not consumed.
	f.setHook(nil)
	rv, err := Read(context.Background(), c, f.link(tok, key))
	if err != nil || rv.Text != "text" || !rv.Anonymous {
		t.Fatalf("reopened: %+v %v", rv, err)
	}
}

func TestReadWrongKey(t *testing.T) {
	f := newFake(t)
	c := f.client(t, "")
	tok := f.add(fixedKey(3), "text", stored{})
	n := f.count()
	_, err := Read(context.Background(), c, f.link(tok, fixedKey(4)))
	if !errors.Is(err, ErrWrongKey) || !strings.Contains(err.Error(), "nothing was consumed") {
		t.Fatalf("error %v", err)
	}
	if f.count() != n+2 {
		t.Fatalf("%d requests, want the status and one reveal", f.count()-n)
	}
	if s := f.get(tok); s.state != "active" || s.failed != 0 {
		t.Fatal("secret consumed or counted")
	}
	// A right key proof with a wrong proof (a faulty creator): counted.
	f.set(func() { f.secrets[tok].verifier = strings.Repeat("0", 64) })
	_, err = Read(context.Background(), c, f.link(tok, fixedKey(3)))
	if !errors.Is(err, ErrWrongKey) || !strings.Contains(err.Error(), "4 attempt(s) left") {
		t.Fatalf("counted: %v", err)
	}
}

func TestReadRevealAnswers(t *testing.T) {
	f := newFake(t)
	c := f.client(t, "")
	key := fixedKey(5)

	// A text that does not open: consumed, integrity error.
	f.setRevealed(map[string]any{"encryptedText": "AQvm_LNcuMssDUaZI6WQ3iGRK4gIg8iiNhOpsnYu-dMoF2eTMvmbWpRI1yivl-6L03VwgcaRxEruSIQs7Q"})
	tok := f.add(key, "text", stored{})
	if _, err := Read(context.Background(), c, f.link(tok, key)); !errors.Is(err, ErrIntegrity) || !errors.Is(err, tte2.ErrAuth) {
		t.Fatalf("integrity: %v", err)
	}
	// A file the status did not announce is reported lost.
	m := derive(key)
	sealed, _ := tte2.SealSecret(m.root, "with file")
	f.setRevealed(map[string]any{"encryptedText": sealed, "fileGrant": "ttg_x"})
	tok = f.add(key, "text", stored{})
	rv, err := Read(context.Background(), c, f.link(tok, key))
	if err != nil || rv.Text != "with file" || !rv.FileLost {
		t.Fatalf("file lost: %+v %v", rv, err)
	}
	f.setRevealed(nil)

	// Problems of the reveal.
	for _, tc := range []struct {
		answer problemAnswer
		want   error
	}{
		{problemAnswer{status: 410, code: "secret-gone", extra: map[string]any{"reason": "read"}}, ErrGone},
		{problemAnswer{status: 429, code: "rate-limited", retryAfter: "60"}, ErrRateLimited},
		{problemAnswer{status: 404, code: "not-found"}, ErrNotFound},
	} {
		tok = f.add(key, "text", stored{})
		f.setHook(func(_ int, r *http.Request) *problemAnswer {
			if r.Method == http.MethodPost {
				a := tc.answer
				return &a
			}
			return nil
		})
		n := f.count()
		if _, err := Read(context.Background(), c, f.link(tok, key)); !errors.Is(err, tc.want) || f.count() != n+2 {
			t.Errorf("%d: %v (%d requests)", tc.answer.status, err, f.count()-n)
		}
	}
	// A server error of the reveal is not retried and passed as is.
	f.setHook(func(_ int, r *http.Request) *problemAnswer {
		if r.Method == http.MethodPost {
			return &problemAnswer{status: 500, code: "internal-error"}
		}
		return nil
	})
	n := f.count()
	var p *client.Problem
	if _, err := Read(context.Background(), c, f.link(tok, key)); !errors.As(err, &p) || p.Status != 500 || f.count() != n+2 {
		t.Fatalf("500: %v", err)
	}
}

func TestReadStatusRetries(t *testing.T) {
	f := newFake(t)
	c := f.client(t, "")
	key := fixedKey(6)
	tok := f.add(key, "text", stored{})
	// Two server errors, then the status: retried.
	f.setHook(func(n int, _ *http.Request) *problemAnswer {
		if n <= 2 {
			return &problemAnswer{status: 502, code: "internal-error"}
		}
		return nil
	})
	if rv, err := Read(context.Background(), c, f.link(tok, key)); err != nil || rv.Text != "text" || f.count() != 4 {
		t.Fatalf("retried: %v (%d requests)", err, f.count())
	}
	// Server errors only: three attempts, then the error.
	tok = f.add(key, "text", stored{})
	f.setHook(func(int, *http.Request) *problemAnswer { return &problemAnswer{status: 503, code: "maintenance"} })
	n := f.count()
	if _, err := Read(context.Background(), c, f.link(tok, key)); err == nil || f.count() != n+statusAttempts {
		t.Fatalf("given up: %v (%d requests)", err, f.count()-n)
	}
	// A 429 is never waited for.
	f.setHook(func(int, *http.Request) *problemAnswer {
		return &problemAnswer{status: 429, code: "rate-limited", retryAfter: "120"}
	})
	n = f.count()
	if _, err := Read(context.Background(), c, f.link(tok, key)); !errors.Is(err, ErrRateLimited) ||
		!strings.Contains(err.Error(), "2m0s") || f.count() != n+1 {
		t.Fatalf("429: %v (%d requests)", err, f.count()-n)
	}
	// The pause ends with the context.
	f.setHook(func(int, *http.Request) *problemAnswer { return &problemAnswer{status: 502, code: "internal-error"} })
	cc := f.client(t, "", client.WithSleep(func(context.Context, time.Duration) error { return context.Canceled }))
	if _, err := Read(context.Background(), cc, f.link(tok, key)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
	// A connection error that is not a problem is passed as is.
	f.setHook(nil)
	f.srv.Close()
	var re *client.RequestError
	if _, err := Read(context.Background(), c, f.link(tok, key)); !errors.As(err, &re) {
		t.Fatalf("closed: %v", err)
	}
}

func TestReadInvalidInput(t *testing.T) {
	f := newFake(t)
	c := f.client(t, "")
	l := f.link(f.add(fixedKey(8), "x", stored{}), fixedKey(8))
	bad := l
	bad.Key = "short"
	if _, err := Read(context.Background(), c, bad); !errors.Is(err, ErrInvalidLink) {
		t.Errorf("key: %v", err)
	}
	bad = l
	bad.Token = "tts_short"
	if _, err := Read(context.Background(), c, bad); !errors.Is(err, ErrInvalidLink) {
		t.Errorf("token: %v", err)
	}
	other := l
	other.Origin = "https://transfer.entity-b.example.com"
	if _, err := Read(context.Background(), c, other); err == nil || !strings.Contains(err.Error(), "entity-b") {
		t.Errorf("origin: %v", err)
	}
	if f.count() != 0 {
		t.Fatalf("%d requests", f.count())
	}
}
