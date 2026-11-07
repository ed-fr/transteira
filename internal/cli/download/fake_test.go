package download

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
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
	"github.com/ed-fr/transteira/internal/tte2"
)

// testToken is the download token of the fake server.
const testToken = "dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf" // gitleaks:allow (fake test token)

// fakeFile is one file served by the fake server.
type fakeFile struct {
	id, name, path string
	data           []byte // bytes served (ciphertext for an encrypted transfer)
	sha            string // digest announced, SHA-256 of data by default
	scan           string
	meta           string // encryptedMetadata
	url            string // downloadUrl announced instead of the real one
	listedSize     int64  // size announced, len(data) by default
	// gen streams the content instead of data (memory test); size is then
	// listedSize and Range is not supported.
	gen func(w io.Writer)
}

func (f *fakeFile) size() int64 {
	if f.listedSize > 0 || f.gen != nil {
		return f.listedSize
	}
	return int64(len(f.data))
}

func (f *fakeFile) digest() string {
	if f.sha != "" {
		return f.sha
	}
	return hexSHA(f.data)
}

// fake is a fake TransTeira server for one download link.
type fake struct {
	t        *testing.T
	srv      *httptest.Server
	files    []*fakeFile
	sender   string
	message  string
	encMsg   string
	e2e      bool
	password string
	code     string // recipient verification code; "" = no verification
	archive  []byte

	// mu is held by the handler for a whole request; tests change the
	// fields once the server runs through set.
	mu           sync.Mutex
	started      bool
	pwLeft       int
	codeLeft     int
	lockedOut    bool
	cut          map[string]int64 // file id (or "archive") → bytes to send before cutting, once
	ignoreRange  bool             // answer 200 to every range request
	shortBody    map[string]int64 // file id → bytes actually sent with a full Content-Length
	requests     []string
	startAnswers int // status of startRecipientVerification (0 = 202)
	// fail, when set, answers a problem with the status it returns for a
	// path (0: serve normally).
	fail func(path string) int
	// hook, when set, sees request n (1-based) first: a status above 0
	// answers a problem with the code, -1 cuts the connection.
	hook func(n int, r *http.Request) (int, string)
	// rangeOverride replaces the Content-Range of a 206 answer, okStatus
	// the 200 status of a file, and noLength drops Content-Length.
	rangeOverride string
	okStatus      int
	noLength      bool
}

// newFake returns a fake server, started by the first call to client.
func newFake(t *testing.T, files ...*fakeFile) *fake {
	t.Helper()
	f := &fake{
		t: t, files: files, sender: "alice@entity-a.example.com", pwLeft: 3, codeLeft: 2,
		cut: map[string]int64{}, shortBody: map[string]int64{},
	}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	t.Cleanup(f.srv.Close)
	return f
}

// client returns a client for the fake server that never sleeps.
func (f *fake) client(t *testing.T) *client.Client {
	t.Helper()
	f.mu.Lock()
	if !f.started {
		f.started = true
		f.srv.StartTLS()
	}
	f.mu.Unlock()
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	c, err := client.New(client.Config{URL: f.srv.URL}, client.WithRootCAs(pool),
		client.WithSleep(func(ctx context.Context, _ time.Duration) error { return ctx.Err() }))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// set runs change under the lock of the handler.
func (f *fake) set(change func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change()
}

// log returns the requests seen, as "METHOD path [Range]".
func (f *fake) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "" || r.Header.Get("Origin") != "" {
		f.t.Errorf("unexpected header on %s", r.URL.Path)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	entry := r.Method + " " + r.URL.Path
	if rg := r.Header.Get("Range"); rg != "" {
		entry += " " + rg
	}
	f.requests = append(f.requests, entry)
	if f.hook != nil {
		switch st, code := f.hook(len(f.requests), r); {
		case st < 0:
			panic(http.ErrAbortHandler)
		case st > 0:
			problem(w, st, code, nil)
			return
		}
	}
	if f.fail != nil {
		if st := f.fail(r.URL.Path); st != 0 {
			problem(w, st, "forced", nil)
			return
		}
	}
	base := apiPrefix + testToken
	switch p := r.URL.Path; {
	case r.Method == http.MethodGet && p == base:
		f.page(w, r)
	case r.Method == http.MethodPost && p == base+"/verification":
		f.startVerification(w, r)
	case r.Method == http.MethodPost && p == base+"/verification/confirm":
		f.confirm(w, r)
	case r.Method == http.MethodPost && p == base+"/unlock":
		f.unlock(w, r)
	case r.Method == http.MethodGet && p == base+"/archive":
		f.serveArchive(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(p, base+"/files/"):
		f.serveFile(w, r, strings.TrimPrefix(p, base+"/files/"))
	default:
		problem(w, http.StatusNotFound, "not-found", nil)
	}
}

func (f *fake) verified(r *http.Request) bool {
	if f.code == "" {
		return true
	}
	c, err := r.Cookie("__Host-tt_rv")
	return err == nil && c.Value == "rv"
}

func (f *fake) unlocked(r *http.Request) bool {
	if f.password == "" {
		return true
	}
	c, err := r.Cookie("__Host-tt_dl")
	return err == nil && c.Value == "dl"
}

func (f *fake) page(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"senderEmail": f.sender, "expiresAt": "2026-11-14T10:00:00Z",
		"passwordProtected": f.password != "", "locked": true,
	}
	if f.e2e {
		out["endToEndEncrypted"] = true
	}
	if f.code != "" {
		out["verificationRequired"] = true
		out["verified"] = f.verified(r)
		out["recipientEmailMasked"] = "c***@customer.example.net"
	}
	if f.verified(r) && f.unlocked(r) {
		out["locked"] = false
		if f.message != "" {
			out["message"] = f.message
		}
		if f.encMsg != "" {
			out["encryptedMessage"] = f.encMsg
		}
		files := []map[string]any{}
		for _, ff := range f.files {
			m := map[string]any{
				"id": ff.id, "name": ff.name, "size": ff.size(), "sha256": ff.digest(),
				"scanStatus": ff.scan, "downloadUrl": apiPrefix + testToken + "/files/" + ff.id,
			}
			if ff.path != "" {
				m["path"] = ff.path
			}
			if ff.url != "" {
				m["downloadUrl"] = ff.url
			}
			if ff.meta != "" {
				m["encryptedMetadata"] = ff.meta
			}
			files = append(files, m)
		}
		out["files"] = files
		if !f.e2e {
			out["archiveUrl"] = apiPrefix + testToken + "/archive"
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (f *fake) startVerification(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["purpose"] != "download" {
		problem(w, http.StatusBadRequest, "validation-failed", nil)
		return
	}
	if f.verified(r) || f.startAnswers == http.StatusNoContent {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	f.codeLeft = 2
	writeJSON(w, http.StatusAccepted, map[string]any{"emailMasked": "c***@customer.example.net", "expiresAt": "2026-11-07T10:15:00Z", "attemptsRemaining": 2})
}

func (f *fake) confirm(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body["code"] == f.code {
		http.SetCookie(w, &http.Cookie{Name: "__Host-tt_rv", Value: "rv", Path: "/", Secure: true, HttpOnly: true})
		w.WriteHeader(http.StatusNoContent)
		return
	}
	f.codeLeft--
	if f.codeLeft <= 0 {
		problem(w, http.StatusGone, "verification-exhausted", nil)
		return
	}
	problem(w, http.StatusUnprocessableEntity, codeCodeInvalid, map[string]any{"attemptsRemaining": f.codeLeft})
}

func (f *fake) unlock(w http.ResponseWriter, r *http.Request) {
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	if !f.verified(r) {
		problem(w, http.StatusUnauthorized, codeVerificationRequired, nil)
		return
	}
	if f.lockedOut {
		w.Header().Set("Retry-After", "900")
		problem(w, http.StatusTooManyRequests, "transfer-locked", nil)
		return
	}
	if body["password"] == f.password {
		http.SetCookie(w, &http.Cookie{Name: "__Host-tt_dl", Value: "dl", Path: "/", Secure: true, HttpOnly: true})
		w.WriteHeader(http.StatusNoContent)
		return
	}
	f.pwLeft--
	if f.pwLeft <= 0 {
		f.lockedOut = true
	}
	problem(w, http.StatusUnauthorized, codePasswordInvalid, map[string]any{"attemptsRemaining": f.pwLeft})
}

func (f *fake) serveArchive(w http.ResponseWriter, r *http.Request) {
	if !f.verified(r) || !f.unlocked(r) {
		problem(w, http.StatusUnauthorized, "download-locked", nil)
		return
	}
	if f.e2e {
		problem(w, http.StatusConflict, "e2e-archive-unavailable", nil)
		return
	}
	f.send(w, "archive", f.archive, http.StatusOK)
}

func (f *fake) serveFile(w http.ResponseWriter, r *http.Request, id string) {
	if !f.verified(r) || !f.unlocked(r) {
		problem(w, http.StatusUnauthorized, "download-locked", nil)
		return
	}
	var ff *fakeFile
	for _, x := range f.files {
		if x.id == id {
			ff = x
		}
	}
	if ff == nil {
		problem(w, http.StatusNotFound, "not-found", nil)
		return
	}
	w.Header().Set("ETag", `"`+ff.digest()+`"`)
	if ff.gen != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(ff.listedSize, 10))
		w.WriteHeader(http.StatusOK)
		ff.gen(w)
		return
	}
	size := int64(len(ff.data))
	start, end := int64(0), size-1
	status := http.StatusOK
	rg := r.Header.Get("Range")
	ignore := f.ignoreRange
	if ir := r.Header.Get("If-Range"); ir != "" && ir != `"`+ff.digest()+`"` {
		rg = ""
	}
	if rg != "" && !ignore {
		spec, ok := strings.CutPrefix(rg, "bytes=")
		a, b, ok2 := strings.Cut(spec, "-")
		s, err := strconv.ParseInt(a, 10, 64)
		if !ok || !ok2 || err != nil || s >= size {
			w.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(size, 10))
			problem(w, http.StatusRequestedRangeNotSatisfiable, "range-not-satisfiable", nil)
			return
		}
		start = s
		if b != "" {
			e, err := strconv.ParseInt(b, 10, 64)
			if err == nil && e < end {
				end = e
			}
		}
		status = http.StatusPartialContent
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
		if f.rangeOverride != "" {
			w.Header().Set("Content-Range", f.rangeOverride)
		}
	}
	if f.okStatus != 0 {
		status = f.okStatus
	}
	f.send(w, id, ff.data[start:end+1], status)
}

// send writes body, cutting the connection once when a cut is armed for key.
func (f *fake) send(w http.ResponseWriter, key string, body []byte, status int) {
	cut, hasCut := f.cut[key]
	if hasCut {
		delete(f.cut, key)
	}
	short, hasShort := f.shortBody[key]
	if !f.noLength {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	}
	w.WriteHeader(status)
	switch {
	case hasShort && f.noLength && short < int64(len(body)):
		_, _ = w.Write(body[:short])
		return
	case hasCut && cut < int64(len(body)):
		_, _ = w.Write(body[:cut])
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		panic(http.ErrAbortHandler)
	case hasShort && short < int64(len(body)):
		_, _ = w.Write(body[:short])
		panic(http.ErrAbortHandler)
	}
	_, _ = w.Write(body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func problem(w http.ResponseWriter, status int, code string, extra map[string]any) {
	body := map[string]any{"type": "about:blank", "title": http.StatusText(status), "status": status, "code": code}
	for k, v := range extra {
		body[k] = v
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// hashWriter computes a SHA-256 as it is written to.
type hashWriter struct{ h hash.Hash }

func newHashWriter() *hashWriter { return &hashWriter{h: sha256.New()} }

func (w *hashWriter) Write(p []byte) (int, error) { return w.h.Write(p) }

func (w *hashWriter) hex() string { return hex.EncodeToString(w.h.Sum(nil)) }

func hexSHA(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// pattern returns n deterministic bytes seeded by seed.
func pattern(seed string, n int) []byte {
	out := make([]byte, 0, n+sha256.Size)
	block := sha256.Sum256([]byte(seed))
	for len(out) < n {
		out = append(out, block[:]...)
		block = sha256.Sum256(block[:])
	}
	return out[:n]
}

// plainFile returns a file of a transfer without encryption.
func plainFile(id, path, name string, data []byte) *fakeFile {
	return &fakeFile{id: id, name: name, path: path, data: data, scan: "clean"}
}

// testChunk is the chunk size of the encrypted fixtures.
const testChunk = tte2.MinChunkSize

// sealedFile encrypts plain as file index of count under key.
func sealedFile(t *testing.T, key []byte, index, count int, path, name string, plain []byte) *fakeFile {
	t.Helper()
	var buf bytes.Buffer
	w, err := tte2.NewWriter(&buf, key, index, tte2.WithChunkSize(testChunk))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	meta, err := tte2.SealMetadata(key, index, tte2.Metadata{
		Index: index, Count: count, Name: name, Path: path, Type: "application/octet-stream",
		Size: int64(len(plain)), SHA256: hexSHA(plain),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &fakeFile{
		id: "fil_e2e" + strconv.Itoa(index), name: "Encrypted file " + strconv.Itoa(index+1),
		data: buf.Bytes(), scan: "not_scanned_e2e", meta: meta,
	}
}

// newKey returns a fresh transfer key and its encoded form.
func newKey(t *testing.T) ([]byte, string) {
	t.Helper()
	k, err := tte2.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := tte2.EncodeKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return k, s
}
