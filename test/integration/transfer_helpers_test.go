package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/test/internal/seeded"
)

// Helpers of the transfer and tus upload tests (CLAUDE.md sections 8, 16.1
// and 17; api/openapi.yaml, "Large uploads (tus)"; threat model T-17, T-21
// to T-27, T-30, T-110, T-123, T-124).

// Transfer and tus API paths and values.
const (
	pathTransfers    = "/api/v1/transfers"
	pathUploads      = "/api/v1/uploads"
	tusVersion       = "1.0.0"
	tusContentType   = "application/offset+octet-stream"
	hdrTusResumable  = "Tus-Resumable"
	hdrUploadOffset  = "Upload-Offset"
	hdrUploadLength  = "Upload-Length"
	hdrUploadExpires = "Upload-Expires"
	hdrIdempotency   = "Idempotency-Key"
	// emptySHA256 is the SHA-256 of the empty content.
	emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	// encSuffix and ckptSuffix are the suffixes of the encrypted file and of
	// its resume checkpoint (internal/storage, documented layout).
	encSuffix  = ".ttef"
	ckptSuffix = ".ckpt"
	// pollInterval is the period of the bounded polls on server state that
	// has no event to wait on (the release of an upload lock, a file on
	// disk).
	pollInterval = 20 * time.Millisecond
	// uploadTimeout bounds a single tus request of the big-file tests.
	uploadTimeout = 30 * time.Minute
)

// fileDecl is the FileDeclaration schema.
type fileDecl struct {
	Name           string `json:"name"`
	Size           int64  `json:"size"`
	MediaType      string `json:"mediaType,omitempty"`
	ExpectedSha256 string `json:"expectedSha256,omitempty"`
}

// transferCreate is the TransferCreate schema.
type transferCreate struct {
	Recipients               []string   `json:"recipients,omitempty"`
	Message                  string     `json:"message,omitempty"`
	ExpiryDays               int        `json:"expiryDays"`
	Password                 *string    `json:"password,omitempty"`
	DeleteAfterFirstDownload bool       `json:"deleteAfterFirstDownload,omitempty"`
	Language                 string     `json:"language,omitempty"`
	Files                    []fileDecl `json:"files"`
	ConfidentialityLevel     string     `json:"confidentialityLevel,omitempty"`
	RecipientVerification    bool       `json:"recipientVerification,omitempty"`
}

// senderFileJSON is the SenderFile schema.
type senderFileJSON struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Size         int64  `json:"size"`
	MediaType    string `json:"mediaType"`
	Sha256       string `json:"sha256"`
	ScanStatus   string `json:"scanStatus"`
	ScanSig      string `json:"scanSignature"`
	UploadURL    string `json:"uploadUrl"`
	UploadOffset *int64 `json:"uploadOffset"`
}

// senderTransferJSON is the SenderTransfer schema.
type senderTransferJSON struct {
	ID                       string           `json:"id"`
	Status                   string           `json:"status"`
	SenderEmail              string           `json:"senderEmail"`
	Recipients               []string         `json:"recipients"`
	Message                  string           `json:"message"`
	ExpiryDays               int              `json:"expiryDays"`
	ExpiresAt                *time.Time       `json:"expiresAt"`
	PasswordProtected        bool             `json:"passwordProtected"`
	DeleteAfterFirstDownload bool             `json:"deleteAfterFirstDownload"`
	TotalBytes               int64            `json:"totalBytes"`
	CreatedAt                time.Time        `json:"createdAt"`
	UploadExpiresAt          *time.Time       `json:"uploadExpiresAt"`
	FinalizedAt              *time.Time       `json:"finalizedAt"`
	DownloadURL              string           `json:"downloadUrl"`
	Files                    []senderFileJSON `json:"files"`
}

// Members allowed by the SenderTransfer and SenderFile schemas, and the
// required ones.
var (
	transferMembers         = []string{"id", "status", "senderEmail", "recipients", "message", "expiryDays", "expiresAt", "passwordProtected", "deleteAfterFirstDownload", "totalBytes", "createdAt", "uploadExpiresAt", "finalizedAt", "downloadUrl", "files", "recipientVerification", "maxDownloads", "confidentialityLevel", "recipientTracking"}
	transferRequiredMembers = []string{"id", "status", "senderEmail", "recipients", "expiryDays", "passwordProtected", "deleteAfterFirstDownload", "totalBytes", "createdAt", "files"}
	fileMembers             = []string{"id", "name", "size", "mediaType", "sha256", "scanStatus", "scanSignature", "uploadUrl", "uploadOffset"}
	fileRequiredMembers     = []string{"id", "name", "size", "scanStatus"}
)

// parseTransfer checks a SenderTransfer body against the members of the
// schema and decodes it.
func parseTransfer(t *testing.T, body []byte) senderTransferJSON {
	t.Helper()
	var members map[string]json.RawMessage
	mustJSON(t, body, &members)
	checkMembers(t, "SenderTransfer", members, transferMembers, transferRequiredMembers)
	var files []map[string]json.RawMessage
	mustJSON(t, members["files"], &files)
	for _, f := range files {
		checkMembers(t, "SenderFile", f, fileMembers, fileRequiredMembers)
	}
	var out senderTransferJSON
	mustJSON(t, body, &out)
	if !strings.HasPrefix(out.ID, "trf_") {
		t.Errorf("transfer id %q, want a trf_ identifier", out.ID)
	}
	for _, f := range out.Files {
		if !strings.HasPrefix(f.ID, "fil_") {
			t.Errorf("file id %q, want a fil_ identifier", f.ID)
		}
		if f.Sha256 != "" && (len(f.Sha256) != 64 || strings.Trim(f.Sha256, "0123456789abcdef") != "") {
			t.Errorf("file %s sha256 %q, want 64 lowercase hex characters", f.ID, f.Sha256)
		}
	}
	return out
}

// checkMembers fails on a member outside allowed or a missing required one.
func checkMembers(t *testing.T, schema string, members map[string]json.RawMessage, allowed, required []string) {
	t.Helper()
	for k := range members {
		if !slices.Contains(allowed, k) {
			t.Errorf("%s has the unexpected member %q", schema, k)
		}
	}
	for _, k := range required {
		if _, ok := members[k]; !ok {
			t.Errorf("%s lacks the required member %q", schema, k)
		}
	}
}

// transferProblem is a Problem with the extension members of the transfer
// operations.
type transferProblem struct {
	problemBody
	MaxTransferBytes *int64   `json:"maxTransferBytes"`
	Files            []string `json:"files"`
	Errors           []struct {
		Field string `json:"field"`
		Code  string `json:"code"`
	} `json:"errors"`
}

// expectTransferProblem is expectProblem decoding the extension members.
func expectTransferProblem(t *testing.T, resp response, status int, code string) transferProblem {
	t.Helper()
	expectProblem(t, resp, status, code)
	var p transferProblem
	mustJSON(t, resp.body, &p)
	return p
}

// createTransfer sends createTransfer with an optional Idempotency-Key.
func (c *depositor) createTransfer(t *testing.T, body transferCreate, key string) response {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	h := c.withCSRF()
	if key != "" {
		h.Set(hdrIdempotency, key)
	}
	return c.send(t, http.MethodPost, pathTransfers, string(b), h)
}

// mustCreate creates a transfer and returns it, failing on anything but 201.
func (c *depositor) mustCreate(t *testing.T, body transferCreate) senderTransferJSON {
	t.Helper()
	resp := c.createTransfer(t, body, "")
	if resp.status != http.StatusCreated {
		t.Fatalf("createTransfer: %d %s", resp.status, resp.body)
	}
	return parseTransfer(t, resp.body)
}

func (c *depositor) getTransfer(t *testing.T, trfID string) response {
	t.Helper()
	return c.send(t, http.MethodGet, pathTransfers+"/"+trfID, "", nil)
}

// mustGet returns the transfer, failing on anything but 200.
func (c *depositor) mustGet(t *testing.T, trfID string) senderTransferJSON {
	t.Helper()
	resp := c.getTransfer(t, trfID)
	if resp.status != http.StatusOK {
		t.Fatalf("getTransfer: %d %s", resp.status, resp.body)
	}
	return parseTransfer(t, resp.body)
}

func (c *depositor) cancelTransfer(t *testing.T, trfID string) response {
	t.Helper()
	return c.send(t, http.MethodDelete, pathTransfers+"/"+trfID, "", c.withCSRF())
}

func (c *depositor) finalize(t *testing.T, trfID string) response {
	t.Helper()
	return c.send(t, http.MethodPost, pathTransfers+"/"+trfID+"/finalize", "", c.withCSRF())
}

// oneFile is a transfer of internal depositors with a single file.
func oneFile(name string, size int64) transferCreate {
	return transferCreate{
		Recipients: []string{"recipient@customer.example.net"}, ExpiryDays: 1,
		Files: []fileDecl{{Name: name, Size: size}},
	}
}

// tusHeaders returns the headers of a tus request of c: session cookie,
// API token, client IP, Tus-Resumable and, for unsafe methods, the CSRF
// token.
func (c *depositor) tusHeaders(method string) http.Header {
	h := http.Header{hdrTusResumable: {tusVersion}}
	if c.ip != "" {
		h.Set(hdrXFF, c.ip)
	}
	if c.cookie != "" {
		h.Set("Cookie", depositCookieName+"="+c.cookie)
	}
	if c.bearer != "" {
		h.Set("Authorization", "Bearer "+c.bearer)
	}
	if method != http.MethodHead && method != http.MethodOptions && c.csrf != "" {
		h.Set(hdrCSRF, c.csrf)
	}
	if method == http.MethodPatch {
		h.Set("Content-Type", tusContentType)
	}
	return h
}

// streamClient sends the streaming tus requests: no overall timeout (a
// request carries its own deadline), no proxy, no keep-alive.
var streamClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
}

// tusRequest sends a tus request with the headers of c changed by edit
// (nil keeps them; a header set to "" is removed) and a streaming body of
// length bytes (nil for none). The response body is read entirely.
func (c *depositor) tusRequest(t *testing.T, method, uploadURL string, edit func(http.Header), body io.Reader, length int64) response {
	t.Helper()
	resp, err := c.tryTus(method, uploadURL, edit, body, length, waitTimeout)
	if err != nil {
		t.Fatalf("%s %s: %v", method, uploadURL, err)
	}
	return resp
}

// tryTus is tusRequest returning the transport errors.
func (c *depositor) tryTus(method, uploadURL string, edit func(http.Header), body io.Reader, length int64, timeout time.Duration) (response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.d.url(uploadURL), body)
	if err != nil {
		return response{}, err
	}
	req.Host = c.host
	h := c.tusHeaders(method)
	if edit != nil {
		edit(h)
	}
	for k, vs := range h {
		if len(vs) == 1 && vs[0] == "" {
			continue
		}
		req.Header[k] = vs
	}
	if body != nil {
		req.ContentLength = length
		if length == 0 {
			req.Body = http.NoBody
		}
	}
	resp, err := streamClient.Do(req)
	if err != nil {
		return response{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return response{}, fmt.Errorf("read body: %w", err)
	}
	return response{status: resp.StatusCode, header: resp.Header, body: b}, nil
}

// head sends a tus HEAD.
func (c *depositor) head(t *testing.T, uploadURL string) response {
	t.Helper()
	return c.tusRequest(t, http.MethodHead, uploadURL, nil, nil, 0)
}

// offsetOf sends a tus HEAD, expects 200 and returns Upload-Offset and
// Upload-Length.
func (c *depositor) offsetOf(t *testing.T, uploadURL string) (offset, length int64) {
	t.Helper()
	resp := c.head(t, uploadURL)
	if resp.status != http.StatusOK {
		t.Fatalf("HEAD %s: status %d, want 200", uploadURL, resp.status)
	}
	expectTusHeaders(t, "HEAD", resp)
	if cc := resp.header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("HEAD Cache-Control = %q, want no-store", cc)
	}
	return headerInt(t, resp, hdrUploadOffset), headerInt(t, resp, hdrUploadLength)
}

// patch sends a tus PATCH of data at offset.
func (c *depositor) patch(t *testing.T, uploadURL string, offset int64, data []byte) response {
	t.Helper()
	return c.tusRequest(t, http.MethodPatch, uploadURL, func(h http.Header) {
		h.Set(hdrUploadOffset, strconv.FormatInt(offset, 10))
	}, bytes.NewReader(data), int64(len(data)))
}

// mustPatch sends a PATCH and expects 204 with the new offset.
func (c *depositor) mustPatch(t *testing.T, uploadURL string, offset int64, data []byte) {
	t.Helper()
	resp := c.patch(t, uploadURL, offset, data)
	if resp.status != http.StatusNoContent {
		t.Fatalf("PATCH %s at %d (%d bytes): status %d, want 204\nserver errors:\n%s", uploadURL, offset, len(data), resp.status, c.d.errorLines())
	}
	expectTusHeaders(t, "PATCH", resp)
	if got, want := headerInt(t, resp, hdrUploadOffset), offset+int64(len(data)); got != want {
		t.Fatalf("PATCH Upload-Offset = %d, want %d", got, want)
	}
}

// upload sends data entirely in one PATCH from offset 0.
func (c *depositor) upload(t *testing.T, uploadURL string, data []byte) {
	t.Helper()
	c.mustPatch(t, uploadURL, 0, data)
}

// terminate sends a tus DELETE.
func (c *depositor) terminate(t *testing.T, uploadURL string) response {
	t.Helper()
	return c.tusRequest(t, http.MethodDelete, uploadURL, nil, nil, 0)
}

// expectTusHeaders asserts the Tus-Resumable header of a tus response.
func expectTusHeaders(t *testing.T, what string, resp response) {
	t.Helper()
	if got := resp.header.Get(hdrTusResumable); got != tusVersion {
		t.Errorf("%s: Tus-Resumable = %q, want %q", what, got, tusVersion)
	}
}

// expectTusError asserts a tus error response: the status, no body, no
// Content-Type and Tus-Resumable (api/openapi.yaml, "Large uploads").
func expectTusError(t *testing.T, what string, resp response, status int) {
	t.Helper()
	if resp.status != status {
		t.Errorf("%s: status %d, want %d; body %q", what, resp.status, status, resp.body)
	}
	if len(resp.body) != 0 {
		t.Errorf("%s: tus error with a body: %q", what, resp.body)
	}
	if ct := resp.header.Get("Content-Type"); ct != "" {
		t.Errorf("%s: tus error with Content-Type %q", what, ct)
	}
	expectTusHeaders(t, what, resp)
}

// headerInt parses an integer header.
func headerInt(t *testing.T, resp response, name string) int64 {
	t.Helper()
	v := resp.header.Get(name)
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		t.Fatalf("%s = %q, want an integer", name, v)
	}
	return n
}

// files returns the file rows of the transfer trfID of tenant A, by
// position.
func (d *depositEnv) files(t *testing.T, trfID string) []store.TransferFile {
	t.Helper()
	fs, err := d.db.TransferFiles().ListByTransfer(context.Background(), d.tenantA.ID, trfID)
	if err != nil {
		t.Fatalf("ListByTransfer(%s): %v", trfID, err)
	}
	return fs
}

// fileRow returns the row of the file fileID of the transfer trfID.
func (d *depositEnv) fileRow(t *testing.T, trfID, fileID string) store.TransferFile {
	t.Helper()
	for _, f := range d.files(t, trfID) {
		if f.ID == fileID {
			return f
		}
	}
	t.Fatalf("file %s of %s not found in the database", fileID, trfID)
	return store.TransferFile{}
}

// tenantDir is the data directory of tenant A.
func (d *depositEnv) tenantDir() string {
	return filepath.Join(d.cfg.DataDir, string(d.tenantA.ID))
}

// encPath and ckptPath are the paths of the encrypted file and of the
// checkpoint of the storage name of tenant A.
func (d *depositEnv) encPath(name string) string { return filepath.Join(d.tenantDir(), name+encSuffix) }

func (d *depositEnv) ckptPath(name string) string {
	return filepath.Join(d.tenantDir(), name+ckptSuffix)
}

// exists reports whether path exists, failing on any other error.
func exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil {
		t.Fatalf("stat %s: %v", filepath.Base(path), err)
	}
	return true
}

// vaults caches the key vault of each server, opened on the master key of
// the server and the store of the test.
var vaults sync.Map // *depositEnv -> *masterkey.Vault

// vault returns a key vault over the master key of the server.
func (d *depositEnv) vault(t *testing.T) *masterkey.Vault {
	t.Helper()
	if v, ok := vaults.Load(d); ok {
		return v.(*masterkey.Vault)
	}
	kr, err := masterkey.Load(d.cfg)
	if err != nil {
		t.Fatalf("masterkey.Load: %v", err)
	}
	v := masterkey.NewVault(d.db, kr, nil)
	vaults.Store(d, v)
	t.Cleanup(func() {
		vaults.Delete(d)
		kr.Close()
	})
	return v
}

// openFile opens the encrypted file of f and returns a reader of its
// plaintext, through the data key opened with the vault.
func (d *depositEnv) openFile(t *testing.T, f store.TransferFile) io.Reader {
	t.Helper()
	dek, err := d.vault(t).Open(context.Background(), d.tenantA.ID, crypto.PurposeDEK, f.DEKKeyID)
	if err != nil {
		t.Fatalf("open the data key of %s: %v", f.ID, err)
	}
	file, err := os.Open(d.encPath(f.StorageName))
	if err != nil {
		t.Fatalf("open the encrypted file of %s: %v", f.ID, err)
	}
	t.Cleanup(func() { _ = file.Close() })
	r, err := crypto.NewReader(bufio.NewReaderSize(file, 1<<20), dek, string(d.tenantA.ID), f.ID)
	clear(dek)
	if err != nil {
		t.Fatalf("decrypt %s: %v", f.ID, err)
	}
	return r
}

// decrypt returns the plaintext of the encrypted file of f.
func (d *depositEnv) decrypt(t *testing.T, f store.TransferFile) []byte {
	t.Helper()
	b, err := io.ReadAll(d.openFile(t, f))
	if err != nil {
		t.Fatalf("decrypt %s: %v", f.ID, err)
	}
	return b
}

// expectKeyDestroyed asserts that the wrapped data key wkID of tenant A is
// gone (crypto-erase, T-110).
func (d *depositEnv) expectKeyDestroyed(t *testing.T, wkID string) {
	t.Helper()
	if wkID == "" {
		t.Fatal("empty wrapped key id")
	}
	if _, err := d.db.WrappedKeys().Get(context.Background(), d.tenantA.ID, wkID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("wrapped key %s: %v, want store.ErrNotFound (destroyed)", wkID, err)
	}
}

// setLimits changes the per-transfer limit and the storage quota of tenant
// A, as the super admin will. The transfer service reads them from the
// database on every creation.
func (d *depositEnv) setLimits(t *testing.T, maxTransfer, quota int64) {
	t.Helper()
	ctx := context.Background()
	tn, err := d.db.Tenants().Get(ctx, d.tenantA.ID)
	if err != nil {
		t.Fatal(err)
	}
	tn.MaxTransferBytes, tn.StorageQuotaBytes = maxTransfer, quota
	tn.MaxTransferCeiling = max(tn.MaxTransferCeiling, maxTransfer)
	if _, err := d.db.Tenants().Update(ctx, tn); err != nil {
		t.Fatalf("update tenant limits: %v", err)
	}
}

// blockEntry adds a blocklist entry to tenant A and returns its identifier.
func (d *depositEnv) blockEntry(t *testing.T, kind store.BlocklistKind, value string) string {
	t.Helper()
	e, err := d.db.Blocklist().Create(context.Background(), d.tenantA.ID, store.BlocklistEntry{
		Kind: kind, Value: value, CreatedBy: "admin@" + domainA,
	})
	if err != nil {
		t.Fatalf("create blocklist entry: %v", err)
	}
	return e.ID
}

// internalSession opens, through Mailpit, an internal session of tenant A
// from insideA for a new address local-<random>@domainA.
func internalSession(t *testing.T, d *depositEnv, local string) (*depositor, string) {
	t.Helper()
	c := d.newDepositor()
	email := uniqueEmail(t, local, domainA)
	c.openSession(t, email, "")
	return c, email
}

// eventually polls cond every pollInterval until it holds, failing after
// waitTimeout. It is used only for server state that has no event to wait
// on.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	tick := time.NewTicker(pollInterval)
	defer tick.Stop()
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not reached within %s", what, waitTimeout)
		}
		<-tick.C
	}
}

// waitUnlocked waits until no request holds the upload lock of any file of
// the transfer trfID: finalize answers state-conflict while an upload is in
// progress and upload-incomplete once it is released (the transfer must
// have an incomplete file).
func (c *depositor) waitUnlocked(t *testing.T, trfID string) {
	t.Helper()
	eventually(t, "upload lock released", func() bool {
		resp := c.finalize(t, trfID)
		var p transferProblem
		mustJSON(t, resp.body, &p)
		switch {
		case resp.status == http.StatusConflict && p.Code == "state-conflict":
			return false
		case resp.status == http.StatusConflict && p.Code == "upload-incomplete":
			return true
		}
		t.Fatalf("finalize while waiting for the lock: %d %s", resp.status, resp.body)
		return false
	})
}

// seededStream is a deterministic pseudo-random stream of size bytes
// (test/internal/seeded): the tests generate their contents on the fly and
// never hold large files in memory.
func seededStream(seed byte, size int64) io.Reader {
	return seeded.Stream(uint64(seed), size)
}

// seededBytes returns the first n bytes of seededStream(seed).
func seededBytes(t *testing.T, seed byte, n int) []byte {
	t.Helper()
	return seeded.Bytes(uint64(seed), n)
}

// seededRange returns a reader of the bytes [from, to) of seededStream.
func seededRange(t *testing.T, seed byte, from, to int64) io.Reader {
	t.Helper()
	return seeded.Range(uint64(seed), from, to-from)
}

// sha256Hex returns the hexadecimal SHA-256 of b.
func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// sameStream compares two readers entirely, chunk by chunk.
func sameStream(t *testing.T, got, want io.Reader) bool {
	t.Helper()
	const n = 1 << 20
	a, b := make([]byte, n), make([]byte, n)
	var pos int64
	for {
		na, ea := io.ReadFull(got, a)
		nb, eb := io.ReadFull(want, b)
		if na != nb || !bytes.Equal(a[:na], b[:nb]) {
			t.Errorf("streams differ near offset %d (%d and %d bytes read)", pos, na, nb)
			return false
		}
		pos += int64(na)
		doneA := errors.Is(ea, io.EOF) || errors.Is(ea, io.ErrUnexpectedEOF)
		doneB := errors.Is(eb, io.EOF) || errors.Is(eb, io.ErrUnexpectedEOF)
		if ea != nil && !doneA {
			t.Errorf("read: %v", ea)
			return false
		}
		if eb != nil && !doneB {
			t.Errorf("read: %v", eb)
			return false
		}
		if doneA || doneB {
			return doneA == doneB
		}
	}
}

// rawPatch opens a TCP connection to the server and writes the head of a
// tus PATCH of c at offset declaring contentLength body bytes; the caller
// writes (part of) the body. It is used to cut a request in the middle of
// its body, which the Go client cannot do.
func (c *depositor) rawPatch(t *testing.T, uploadURL string, offset, contentLength int64) *net.TCPConn {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: waitTimeout}).DialContext(context.Background(), "tcp", c.d.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tc := conn.(*net.TCPConn)
	t.Cleanup(func() { _ = tc.Close() })
	var b strings.Builder
	fmt.Fprintf(&b, "PATCH %s HTTP/1.1\r\nHost: %s\r\n", uploadURL, c.host)
	for k, vs := range c.tusHeaders(http.MethodPatch) {
		fmt.Fprintf(&b, "%s: %s\r\n", k, vs[0])
	}
	fmt.Fprintf(&b, "%s: %d\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", hdrUploadOffset, offset, contentLength)
	if _, err := io.WriteString(tc, b.String()); err != nil {
		t.Fatalf("write PATCH head: %v", err)
	}
	return tc
}

// readRawResponse reads the response of a raw request.
func readRawResponse(t *testing.T, conn net.Conn) response {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(waitTimeout))
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPatch})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return response{status: resp.StatusCode, header: resp.Header, body: b}
}

// newHashingReader returns a reader computing the SHA-256 and the size of
// what is read through it (test/internal/seeded).
func newHashingReader(r io.Reader) *seeded.HashingReader {
	return seeded.NewHashingReader(r)
}

// errorLines returns the error and warning lines of the application log,
// to explain an unexpected status.
func (d *depositEnv) errorLines() string {
	var out []string
	for _, l := range strings.Split(d.appLog.String(), "\n") {
		if strings.Contains(l, `"level":"ERROR"`) || strings.Contains(l, `"level":"WARN"`) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}
