package secret

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/tte2"
)

// testAPIToken is the API token of the clients built with a token.
const testAPIToken = "tt_" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ" // gitleaks:allow (fake test token)

// stored is one secret held by the fake server.
type stored struct {
	sealed, verifier, keyVerifier string
	state                         string // active, read, expired, deleted, locked
	express, anonymous            bool
	passphrase, file              bool
	failed                        int
}

// request is what the fake server saw of one request.
type request struct {
	method, path string
	header       http.Header
	body         []byte
}

// problemAnswer is a problem the fake server answers instead of serving.
type problemAnswer struct {
	status     int
	code       string
	retryAfter string
	extra      map[string]any
}

// fake is a fake TransTeira server for secrets.
type fake struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	secrets  map[string]*stored // by token
	requests []request
	// hook, when set, sees request n (1-based): a non-nil answer is sent
	// instead of serving.
	hook func(n int, r *http.Request) *problemAnswer
	// created replaces the answer of a creation when set.
	created map[string]any
	// revealed replaces the answer of a reveal when set.
	revealed map[string]any
	// status replaces the answer of a status call when set.
	status map[string]any
}

// newFake starts a fake server.
func newFake(t *testing.T) *fake {
	t.Helper()
	f := &fake{t: t, secrets: map[string]*stored{}}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

// client returns a client of the fake server that never sleeps; token is
// its API token ("" for none).
func (f *fake) client(t *testing.T, token string, opts ...client.Option) *client.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	opts = append([]client.Option{
		client.WithRootCAs(pool),
		client.WithSleep(func(ctx context.Context, _ time.Duration) error { return ctx.Err() }),
	}, opts...)
	c, err := client.New(client.Config{URL: f.srv.URL, Token: token}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// set runs change under the lock of the server, to change its fields.
func (f *fake) set(change func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change()
}

// setHook installs hook under the lock.
func (f *fake) setHook(hook func(n int, r *http.Request) *problemAnswer) {
	f.set(func() { f.hook = hook })
}

// setRevealed replaces the answer of the reveals under the lock.
func (f *fake) setRevealed(m map[string]any) { f.set(func() { f.revealed = m }) }

// setCreated replaces the answer of the creations under the lock.
func (f *fake) setCreated(m map[string]any) { f.set(func() { f.created = m }) }

// get returns a copy of the secret of token.
func (f *fake) get(token string) stored {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *f.secrets[token]
}

// count returns the number of requests seen.
func (f *fake) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// last returns the last request seen.
func (f *fake) last() request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[len(f.requests)-1]
}

// add stores a secret sealed under key (no passphrase) and returns its
// token.
func (f *fake) add(key []byte, text string, s stored) string {
	f.t.Helper()
	m := derive(key)
	sealed, err := tte2.SealSecret(m.root, text)
	if err != nil {
		f.t.Fatal(err)
	}
	token, err := id.NewSecretToken()
	if err != nil {
		f.t.Fatal(err)
	}
	s.sealed = sealed
	s.verifier = tte2.EncodeProof(tte2.SecretVerifier(m.proof))
	s.keyVerifier = tte2.EncodeProof(tte2.SecretVerifier(m.keyProof))
	if s.state == "" {
		s.state = "active"
	}
	f.mu.Lock()
	f.secrets[token] = &s
	f.mu.Unlock()
	return token
}

// link returns the link of token with key.
func (f *fake) link(token string, key []byte) Link {
	f.t.Helper()
	enc, err := tte2.EncodeKey(key)
	if err != nil {
		f.t.Fatal(err)
	}
	l, err := ParseLink(f.srv.URL + "/s/" + token + "#k=" + enc)
	if err != nil {
		f.t.Fatal(err)
	}
	return l
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, request{method: r.Method, path: r.URL.Path, header: r.Header.Clone(), body: body})
	if f.hook != nil {
		if a := f.hook(len(f.requests), r); a != nil {
			writeProblem(w, a)
			return
		}
	}
	rest, isLink := strings.CutPrefix(r.URL.Path, linkPath)
	switch {
	case r.Method == http.MethodPost && r.URL.Path == createPath:
		f.create(w, r, body)
	case isLink && r.Method == http.MethodGet && !strings.Contains(rest, "/"):
		f.statusOf(w, rest)
	case isLink && r.Method == http.MethodPost && strings.HasSuffix(rest, "/reveal"):
		f.reveal(w, strings.TrimSuffix(rest, "/reveal"), body)
	default:
		writeProblem(w, &problemAnswer{status: http.StatusNotFound, code: "not-found"})
	}
}

// create implements createExpressSecret with the checks of the server.
func (f *fake) create(w http.ResponseWriter, r *http.Request, body []byte) {
	var in map[string]string
	dec := json.NewDecoder(bytes.NewReader(body))
	if r.Header.Get("Content-Type") != "application/json" || dec.Decode(&in) != nil || len(in) != 4 ||
		!ValidDuration(in["expiresIn"]) {
		writeProblem(w, &problemAnswer{status: http.StatusBadRequest, code: "validation-failed"})
		return
	}
	_, errV := tte2.ParseProof(in["verifier"])
	_, errK := tte2.ParseProof(in["keyVerifier"])
	if errV != nil || errK != nil || tte2.CheckSecretFraming(in["encryptedText"]) != nil || tte2.SecretTextIsEmpty(in["encryptedText"]) {
		writeProblem(w, &problemAnswer{status: http.StatusBadRequest, code: "secret-format-invalid"})
		return
	}
	token, _ := id.NewSecretToken()
	f.secrets[token] = &stored{
		sealed: in["encryptedText"], verifier: in["verifier"], keyVerifier: in["keyVerifier"],
		state: "active", express: true, anonymous: r.Header.Get("Authorization") == "",
	}
	out := map[string]any{"id": id.New(id.Secret), "token": token, "state": "active", "expiresAt": "2026-11-18T09:00:00Z"}
	if f.created != nil {
		out = f.created
	}
	writeJSON(w, http.StatusCreated, out)
}

// lookup finds the secret of token, answering 404 or 410 when it cannot
// be served.
func (f *fake) lookup(w http.ResponseWriter, token string) *stored {
	s, ok := f.secrets[token]
	switch {
	case !ok:
		writeProblem(w, &problemAnswer{status: http.StatusNotFound, code: "not-found"})
		return nil
	case s.state != "active":
		writeProblem(w, &problemAnswer{status: http.StatusGone, code: "secret-gone", extra: map[string]any{"reason": s.state}})
		return nil
	}
	return s
}

// statusOf implements getSecretLink.
func (f *fake) statusOf(w http.ResponseWriter, token string) {
	s := f.lookup(w, token)
	if s == nil {
		return
	}
	out := map[string]any{"state": "active", "expiresAt": "2026-11-18T09:00:00Z", "file": nil}
	if s.passphrase {
		out["passphrase"] = map[string]any{"kdf": tte2.PassphraseKDF, "iterations": tte2.PassphraseIterations, "salt": "fYFgqj_v4D4pjxFwzmjGvQ"}
	}
	if s.file {
		out["file"] = map[string]any{"size": 2097200}
	}
	if s.express {
		out["express"] = true
		out["anonymous"] = s.anonymous
	}
	if f.status != nil {
		out = f.status
	}
	writeJSON(w, http.StatusOK, out)
}

// reveal implements revealSecret: key proof first, then the counted proof.
func (f *fake) reveal(w http.ResponseWriter, token string, body []byte) {
	s := f.lookup(w, token)
	if s == nil {
		return
	}
	var in map[string]string
	if json.Unmarshal(body, &in) != nil || len(in) != 2 {
		writeProblem(w, &problemAnswer{status: http.StatusBadRequest, code: "validation-failed"})
		return
	}
	keyProof, errK := tte2.ParseProof(in["keyProof"])
	proof, errP := tte2.ParseProof(in["proof"])
	keyVerifier, _ := tte2.ParseProof(s.keyVerifier)
	verifier, _ := tte2.ParseProof(s.verifier)
	switch {
	case errK != nil || errP != nil:
		writeProblem(w, &problemAnswer{status: http.StatusBadRequest, code: "validation-failed"})
		return
	case !tte2.VerifierMatches(keyVerifier, keyProof):
		writeProblem(w, &problemAnswer{status: http.StatusForbidden, code: "secret-proof-invalid"})
		return
	case !tte2.VerifierMatches(verifier, proof):
		s.failed++
		writeProblem(w, &problemAnswer{
			status: http.StatusForbidden, code: "secret-proof-invalid",
			extra: map[string]any{"attemptsRemaining": 5 - s.failed},
		})
		return
	}
	s.state = "read"
	out := map[string]any{"encryptedText": s.sealed}
	if f.revealed != nil {
		out = f.revealed
	}
	writeJSON(w, http.StatusOK, out)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeProblem(w http.ResponseWriter, a *problemAnswer) {
	out := map[string]any{"type": "about:blank", "title": http.StatusText(a.status), "status": a.status, "code": a.code}
	for k, v := range a.extra {
		out[k] = v
	}
	if a.retryAfter != "" {
		w.Header().Set("Retry-After", a.retryAfter)
	}
	w.Header().Set("X-Request-Id", "req_"+strconv.Itoa(a.status))
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(a.status)
	_ = json.NewEncoder(w).Encode(out)
}

// fixedKey returns a 32-byte key filled with b.
func fixedKey(b byte) []byte { return bytes.Repeat([]byte{b}, tte2.KeySize) }
