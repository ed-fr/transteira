package integration_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/tte2"
)

// Helpers of the end-to-end encryption tests (CLAUDE.md section 22;
// docs/architecture/e2e-format.md; api/openapi.yaml createTransfer
// endToEndEncrypted, appendUploadChunk, downloadArchive; threat model
// 6.53, T-318 to T-327). The client side is played by the Go reference
// implementation of the format, internal/tte2.

// Problem codes of the end-to-end encryption (api/openapi.yaml).
const (
	codeE2EForbidden      = "e2e-forbidden"
	codeE2ERequired       = "e2e-required"
	codeE2EFormatInvalid  = "e2e-format-invalid"
	codeE2EArchiveUnavail = "e2e-archive-unavailable"
	// scanE2E is the scan status of the files of an encrypted transfer.
	scanE2E = "not_scanned_e2e"
)

// e2ePlain is a file to encrypt: the name, folder and media type go into the
// sealed metadata, never to the server.
type e2ePlain struct {
	name, path, mediaType string
	content               []byte
	// chunk is the plaintext chunk size (0: the default of the format).
	chunk int
}

// e2eSet is a whole encrypted transfer prepared by the client: the transfer
// key, the ciphertext and sealed metadata of every file, the sealed
// message, and the createTransfer request that declares them.
type e2eSet struct {
	key     []byte
	keyB64  string
	plains  []e2ePlain
	cipher  [][]byte
	sealed  []string
	message string
	sealMsg string
}

// encryptFile returns the TTE2 stream of plain as file index of a transfer
// of key.
func encryptFile(t *testing.T, key []byte, index int, p e2ePlain) []byte {
	t.Helper()
	var buf bytes.Buffer
	var opts []tte2.Option
	if p.chunk != 0 {
		opts = append(opts, tte2.WithChunkSize(p.chunk))
	}
	w, err := tte2.NewWriter(&buf, key, index, opts...)
	if err != nil {
		t.Fatalf("tte2.NewWriter: %v", err)
	}
	if _, err := w.Write(p.content); err != nil {
		t.Fatalf("tte2 write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("tte2 close: %v", err)
	}
	return buf.Bytes()
}

// newE2ESet encrypts files (and message, when not empty) under a fresh
// transfer key.
func newE2ESet(t *testing.T, message string, files ...e2ePlain) *e2eSet {
	t.Helper()
	key, err := tte2.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	keyB64, err := tte2.EncodeKey(key)
	if err != nil {
		t.Fatal(err)
	}
	s := &e2eSet{key: key, keyB64: keyB64, plains: files, message: message}
	for i, p := range files {
		s.cipher = append(s.cipher, encryptFile(t, key, i, p))
		sealed, err := tte2.SealMetadata(key, i, tte2.Metadata{
			Index: i, Count: len(files), Name: p.name, Path: p.path, Type: p.mediaType,
			Size: int64(len(p.content)), SHA256: sha256Hex(p.content),
		})
		if err != nil {
			t.Fatalf("tte2.SealMetadata: %v", err)
		}
		s.sealed = append(s.sealed, sealed)
	}
	if message != "" {
		if s.sealMsg, err = tte2.SealMessage(key, message); err != nil {
			t.Fatalf("tte2.SealMessage: %v", err)
		}
	}
	return s
}

// e2eName is the generic name of the file index (0-based).
func e2eName(index int) string { return fmt.Sprintf("file-%d.tte2", index+1) }

// create returns the createTransfer request of s to recipients.
func (s *e2eSet) create(recipients ...string) transferCreate {
	req := transferCreate{
		Recipients: recipients, ExpiryDays: 7, Language: "en",
		EndToEndEncrypted: true, EncryptedMessage: s.sealMsg,
	}
	for i := range s.plains {
		req.Files = append(req.Files, fileDecl{
			Name: e2eName(i), Size: int64(len(s.cipher[i])), EncryptedMetadata: s.sealed[i],
			ExpectedSha256: sha256Hex(s.cipher[i]),
		})
	}
	return req
}

// decrypt opens the ciphertext body as file index of s and checks it against
// the sealed metadata: the plaintext, its size and its SHA-256.
func (s *e2eSet) decrypt(t *testing.T, index int, body []byte, sealed string) {
	t.Helper()
	meta, err := tte2.OpenMetadata(s.key, index, sealed)
	if err != nil {
		t.Fatalf("tte2.OpenMetadata(%d): %v", index, err)
	}
	r, err := tte2.NewReader(bytes.NewReader(body), s.key, index)
	if err != nil {
		t.Fatalf("tte2.NewReader(%d): %v", index, err)
	}
	plain, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("decrypt file %d: %v", index, err)
	}
	p := s.plains[index]
	if meta.Name != p.name || meta.Path != p.path || meta.Type != p.mediaType || meta.Count != len(s.plains) {
		t.Errorf("file %d metadata = %+v, want %q in %q (%s) of %d files", index, meta, p.name, p.path, p.mediaType, len(s.plains))
	}
	if !bytes.Equal(plain, p.content) {
		t.Errorf("file %d: decrypted %d bytes, want the %d bytes sent", index, len(plain), len(p.content))
	}
	if got := sha256Hex(plain); got != meta.SHA256 || int64(len(plain)) != meta.Size {
		t.Errorf("file %d: plaintext sha256 %s size %d, metadata says %s size %d", index, got, len(plain), meta.SHA256, meta.Size)
	}
}

// setE2EPolicy sets the end-to-end encryption policy of tenant A, as the
// super admin.
func (o *opsEnv) setE2EPolicy(t *testing.T, policy string) {
	t.Helper()
	path := tenantPath(o.tid, "")
	resp := mustStatus(t, "updateTenant e2ePolicy", o.sa.mergePatch(t, path, `{"e2ePolicy":"`+policy+`"}`), http.StatusOK)
	expectContract(t, "updateTenant", http.MethodPatch, path, resp)
	var tn struct {
		E2EPolicy string `json:"e2ePolicy"`
	}
	mustJSON(t, resp.body, &tn)
	if tn.E2EPolicy != policy {
		t.Errorf("updateTenant: e2ePolicy %q, want %q", tn.E2EPolicy, policy)
	}
}

// levelJSON is a confidentiality level with the optional e2ePolicy rule:
// "" omits the member, "null" sends null, anything else is the policy.
func levelJSON(key string, isDefault bool, e2e string) string {
	rule := ""
	switch e2e {
	case "":
	case "null":
		rule = `,"e2ePolicy":null`
	default:
		rule = `,"e2ePolicy":"` + e2e + `"`
	}
	return fmt.Sprintf(`{"key":%q,"labels":{"en":%q,"fr":%q},"isDefault":%t,"rules":{"requireRecipientVerification":false,`+
		`"requirePassword":false,"allowedExpiryDays":[1,7,30],"internalRecipientsOnly":false,"forceDeleteAfterFirstDownload":false,`+
		`"maxDownloads":null%s}}`, key, key, key, isDefault, rule)
}

// putLevels replaces the confidentiality levels of tenant tid as c.
func putLevels(t *testing.T, c *adminClient, tid string, items ...string) response {
	t.Helper()
	path := tenantPath(tid, "/confidentiality-levels")
	return c.send(t, http.MethodPut, path, `{"items":[`+strings.Join(items, ",")+`]}`, http.Header{hdrCSRF: {c.csrf}})
}

// plainRequest is a plaintext request of one small file at level.
func plainRequest(level string, recipients ...string) transferCreate {
	return transferCreate{
		Recipients: recipients, ExpiryDays: 7, ConfidentialityLevel: level,
		Files: []fileDecl{{Name: "a.txt", Size: 5}},
	}
}

// expectNoE2ELeak fails when a mail body (text and HTML) carries the transfer
// key, the sealed message, the plaintext message or a plaintext file name or
// folder of s.
func expectNoE2ELeak(t *testing.T, what string, m mpMessage, s *e2eSet) {
	t.Helper()
	body := m.Text + "\n" + m.HTML + "\n" + m.Subject
	secrets := map[string]string{"transfer key": s.keyB64, "plaintext message": s.message, "sealed message": s.sealMsg}
	for i, p := range s.plains {
		secrets[fmt.Sprintf("name %d", i)] = p.name
		if p.path != "" {
			secrets[fmt.Sprintf("path %d", i)] = p.path
		}
		secrets[fmt.Sprintf("sealed metadata %d", i)] = s.sealed[i]
	}
	for label, v := range secrets {
		if v != "" && strings.Contains(body, v) {
			t.Errorf("%s carries the %s %q", what, label, v)
		}
	}
}
