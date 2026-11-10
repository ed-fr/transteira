package upload

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
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/cli/client"
)

const testToken = "tt_testtoken0123456789"

// fakeUpload is one tus upload of the fake server.
type fakeUpload struct {
	id       string
	tr       *fakeTransfer
	length   int64
	offset   int64
	received int64 // body bytes received, resends included
	h        hash.Hash
	data     bytes.Buffer
}

// fakeTransfer is one transfer of the fake server.
type fakeTransfer struct {
	id        string
	body      []byte
	req       createRequest
	status    string
	uploads   []*fakeUpload
	linkGiven bool
	polls     int
	canceled  bool
}

// fakeServer implements just enough of the API for the uploader, strict
// on the tus headers.
type fakeServer struct {
	t    *testing.T
	srv  *httptest.Server
	mu   sync.Mutex
	keep bool // keep the uploaded bytes

	transfers map[string]*fakeTransfer
	byKey     map[string]*fakeTransfer
	uploads   map[string]*fakeUpload
	requests  []string
	nextID    int

	// hook, when set, may answer a request itself (returns true).
	hook func(w http.ResponseWriter, r *http.Request) bool
	// cut, when set, returns the number of body bytes a PATCH may deliver
	// before the connection is closed, or -1.
	cut func(up *fakeUpload, offset int64) int64
	// afterPatch is called after each successful PATCH (lock not held).
	afterPatch func(up *fakeUpload)
	// scanPolls is the number of GETs a transfer stays scanning; outcome
	// is "available" (default), "rejected" or "infected" (file 0).
	scanPolls int
	outcome   string
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	fs := &fakeServer{
		t: t, keep: true,
		transfers: map[string]*fakeTransfer{}, byKey: map[string]*fakeTransfer{}, uploads: map[string]*fakeUpload{},
	}
	fs.srv = httptest.NewTLSServer(http.HandlerFunc(fs.serve))
	t.Cleanup(fs.srv.Close)
	return fs
}

// client returns a client trusting the fake server, whose pauses are
// recorded in sleeps instead of waited.
func (fs *fakeServer) client(t *testing.T, token string, sleeps *[]time.Duration) *client.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(fs.srv.Certificate())
	var mu sync.Mutex
	c, err := client.New(client.Config{URL: fs.srv.URL, Token: token}, client.WithRootCAs(pool),
		client.WithSleep(func(ctx context.Context, d time.Duration) error {
			mu.Lock()
			if sleeps != nil {
				*sleeps = append(*sleeps, d)
			}
			mu.Unlock()
			return ctx.Err()
		}))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (fs *fakeServer) count(prefix string) int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n := 0
	for _, r := range fs.requests {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

// settle closes the server and waits for its in-flight handlers, so that
// a test may read the server state once Run has returned. Run can return
// while a handler still consumes an aborted request body (a PATCH whose
// client gave up halfway) and keeps updating the upload; reading the state
// before that handler ends is a data race and gives a value that is not yet
// final. Closing is idempotent, so the cleanup's Close stays harmless.
func (fs *fakeServer) settle() {
	fs.srv.Close()
}

// only returns the single transfer of the server.
func (fs *fakeServer) only() *fakeTransfer {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.transfers) != 1 {
		fs.t.Fatalf("%d transfers on the server", len(fs.transfers))
	}
	for _, tr := range fs.transfers {
		return tr
	}
	return nil
}

func problem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "code": code, "title": http.StatusText(status)})
}

func (fs *fakeServer) serve(w http.ResponseWriter, r *http.Request) {
	fs.mu.Lock()
	fs.requests = append(fs.requests, r.Method+" "+r.URL.Path)
	hook := fs.hook
	fs.mu.Unlock()
	if hook != nil && hook(w, r) {
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		w.Header().Set("WWW-Authenticate", "Bearer")
		if strings.HasPrefix(r.URL.Path, "/api/v1/uploads/") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		problem(w, http.StatusUnauthorized, "invalid-credentials")
		return
	}
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/api/v1/uploads/"):
		fs.tus(w, r, strings.TrimPrefix(path, "/api/v1/uploads/"))
	case path == transfersPath && r.Method == http.MethodPost:
		fs.create(w, r)
	case strings.HasSuffix(path, "/finalize") && r.Method == http.MethodPost:
		fs.finalize(w, strings.TrimSuffix(strings.TrimPrefix(path, transfersPath+"/"), "/finalize"))
	case strings.HasPrefix(path, transfersPath+"/"):
		fs.transfer(w, r, strings.TrimPrefix(path, transfersPath+"/"))
	default:
		problem(w, http.StatusNotFound, "not-found")
	}
}

func (fs *fakeServer) view(tr *fakeTransfer) transfer {
	v := transfer{ID: tr.id, Status: tr.status}
	if tr.status == statusAvailable {
		exp := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
		v.ExpiresAt = &exp
	}
	for i, up := range tr.uploads {
		d := tr.req.Files[i]
		f := senderFile{Name: d.Name, Size: d.Size, ScanStatus: "pending"}
		switch tr.status {
		case statusUploading:
			f.UploadURL = "/api/v1/uploads/" + up.id
		case statusScanning:
			f.ScanStatus = "scanning"
		case statusAvailable, statusRejected:
			f.SHA256 = hex.EncodeToString(up.h.Sum(nil))
			f.ScanStatus = "clean"
			if tr.req.EndToEndEncrypted {
				f.ScanStatus = "not_scanned_e2e"
			}
			if tr.status == statusRejected || (fs.outcome == "infected" && i == 0) {
				f.ScanStatus = "infected"
			}
		}
		v.Files = append(v.Files, f)
	}
	return v
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (fs *fakeServer) create(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	body, _ := io.ReadAll(r.Body)
	var req createRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if key == "" || r.Header.Get("Content-Type") != "application/json" || dec.Decode(&req) != nil || len(req.Files) == 0 {
		problem(w, http.StatusBadRequest, "validation-failed")
		return
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if tr, ok := fs.byKey[key]; ok {
		if !bytes.Equal(tr.body, body) {
			problem(w, http.StatusConflict, "state-conflict")
			return
		}
		writeJSON(w, http.StatusCreated, fs.view(tr))
		return
	}
	fs.nextID++
	tr := &fakeTransfer{id: fmt.Sprintf("trf_%026d", fs.nextID), body: body, req: req, status: statusUploading}
	for i, f := range req.Files {
		up := &fakeUpload{id: fmt.Sprintf("upl_%d_%d_abcdefghijkl", fs.nextID, i), tr: tr, length: f.Size, h: sha256.New()}
		tr.uploads = append(tr.uploads, up)
		fs.uploads[up.id] = up
	}
	fs.transfers[tr.id] = tr
	fs.byKey[key] = tr
	writeJSON(w, http.StatusCreated, fs.view(tr))
}

func (fs *fakeServer) transfer(w http.ResponseWriter, r *http.Request, id string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	tr, ok := fs.transfers[id]
	if !ok {
		problem(w, http.StatusNotFound, "not-found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		if tr.status == statusScanning {
			tr.polls++
			if tr.polls > fs.scanPolls {
				tr.status = statusAvailable
				if fs.outcome == "rejected" {
					tr.status = statusRejected
				}
			}
		}
		writeJSON(w, http.StatusOK, fs.view(tr))
	case http.MethodDelete:
		if tr.status != statusUploading {
			problem(w, http.StatusConflict, "state-conflict")
			return
		}
		tr.canceled = true
		delete(fs.transfers, id)
		w.WriteHeader(http.StatusNoContent)
	default:
		problem(w, http.StatusMethodNotAllowed, "method-not-allowed")
	}
}

func (fs *fakeServer) finalize(w http.ResponseWriter, id string) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	tr, ok := fs.transfers[id]
	if !ok {
		problem(w, http.StatusNotFound, "not-found")
		return
	}
	if tr.status == statusUploading {
		for i, up := range tr.uploads {
			if up.offset != up.length {
				problem(w, http.StatusConflict, codeUploadIncomplete)
				return
			}
			if exp := tr.req.Files[i].ExpectedSHA256; exp != "" && exp != hex.EncodeToString(up.h.Sum(nil)) {
				problem(w, http.StatusConflict, codeChecksumMismatch)
				return
			}
		}
		tr.status = statusScanning
	}
	v := fs.view(tr)
	if tr.req.LinkOnly && !tr.linkGiven {
		tr.linkGiven = true
		v.DownloadURL = fs.srv.URL + "/d/dl_linkonly0123456789"
	}
	writeJSON(w, http.StatusAccepted, v)
}

func (fs *fakeServer) tus(w http.ResponseWriter, r *http.Request, id string) {
	if r.Header.Get("Tus-Resumable") != tusVersion {
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	fs.mu.Lock()
	up, ok := fs.uploads[id]
	if ok && (up.tr.canceled || up.tr.status != statusUploading) {
		fs.mu.Unlock()
		w.WriteHeader(http.StatusGone)
		return
	}
	fs.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodHead:
		fs.mu.Lock()
		w.Header().Set("Upload-Offset", strconv.FormatInt(up.offset, 10))
		w.Header().Set("Upload-Length", strconv.FormatInt(up.length, 10))
		fs.mu.Unlock()
		w.Header().Set("Tus-Resumable", tusVersion)
		w.WriteHeader(http.StatusOK)
	case http.MethodPatch:
		fs.patch(w, r, up)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (fs *fakeServer) patch(w http.ResponseWriter, r *http.Request, up *fakeUpload) {
	if r.Header.Get("Content-Type") != tusType {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	offset, err := strconv.ParseInt(r.Header.Get("Upload-Offset"), 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	fs.mu.Lock()
	if offset != up.offset {
		fs.mu.Unlock()
		w.WriteHeader(http.StatusConflict)
		return
	}
	limit := int64(-1)
	if fs.cut != nil {
		limit = fs.cut(up, offset)
	}
	fs.mu.Unlock()
	buf := make([]byte, 32<<10)
	var got int64
	for {
		want := int64(len(buf))
		if limit >= 0 {
			want = min(want, limit-got)
			if want == 0 {
				panic(http.ErrAbortHandler)
			}
		}
		n, rerr := r.Body.Read(buf[:want])
		fs.mu.Lock()
		if up.offset+int64(n) > up.length {
			fs.mu.Unlock()
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		up.h.Write(buf[:n])
		if fs.keep {
			up.data.Write(buf[:n])
		}
		up.offset += int64(n)
		up.received += int64(n)
		fs.mu.Unlock()
		got += int64(n)
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	fs.mu.Lock()
	off := up.offset
	after := fs.afterPatch
	fs.mu.Unlock()
	if after != nil {
		after(up)
	}
	w.Header().Set("Tus-Resumable", tusVersion)
	w.Header().Set("Upload-Offset", strconv.FormatInt(off, 10))
	w.WriteHeader(http.StatusNoContent)
}
