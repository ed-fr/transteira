package httpisolation_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tte2"
)

// Isolation of the end-to-end encrypted transfers (V2 step 7; threat model
// 6.53, T-318 to T-327). The generic cases of operations_test.go cover each
// operation with a plaintext transfer; these cases add the transfers whose
// files are ciphertext of tenant A: every download, view, upload and admin
// endpoint answers a foreign tenant exactly as for an unknown object (404,
// never the "this is an encrypted transfer" answers: 409
// e2e-archive-unavailable, 400 e2e-format-invalid, the sealed metadata or
// message), and the end-to-end policy of a tenant is its own.

// e2eFixture is an end-to-end encrypted transfer of tenant A, created by its
// colleague session.
type e2eFixture struct {
	trfID, token, fileID, uploadID string
	ciphertext                     []byte
	sealedMeta, sealedMsg          string
}

// e2eOps are the operations the cases send, as the specification names them.
var (
	opGetDownload = operation{id: "getDownload", verb: http.MethodGet, template: "/downloads/{linkToken}", base: "/api/v1"}
	opDownloadOne = operation{id: "downloadFile", verb: http.MethodGet, template: "/downloads/{linkToken}/files/{fileId}", base: "/api/v1"}
	opArchive     = operation{id: "downloadArchive", verb: http.MethodGet, template: "/downloads/{linkToken}/archive", base: "/api/v1"}
	opGetTransfer = operation{id: "getTransfer", verb: http.MethodGet, template: "/transfers/{transferId}", base: "/api/v1"}
	opFinalize    = operation{id: "finalizeTransfer", verb: http.MethodPost, template: "/transfers/{transferId}/finalize", base: "/api/v1"}
	opCancel      = operation{id: "cancelTransfer", verb: http.MethodDelete, template: "/transfers/{transferId}", base: "/api/v1"}
	opCreate      = operation{id: "createTransfer", verb: http.MethodPost, template: "/transfers", base: "/api/v1"}
	opHeadUpload  = operation{id: "getUploadOffset", verb: http.MethodHead, template: "/uploads/{uploadId}", base: "/api/v1"}
	opPatchUpload = operation{id: "appendUploadChunk", verb: http.MethodPatch, template: "/uploads/{uploadId}", base: "/api/v1"}
	opTermUpload  = operation{id: "terminateUpload", verb: http.MethodDelete, template: "/uploads/{uploadId}", base: "/api/v1"}
	opPublicInfo  = operation{id: "getPublicTenant", verb: http.MethodGet, template: "/tenant", base: "/api/v1"}
)

// e2eCreateBody builds the createTransfer body of an encrypted transfer of
// one file of 'plain' bytes, and returns it with the ciphertext and the
// sealed values.
func e2eCreateBody(t *testing.T, plain []byte) (body string, f e2eFixture) {
	t.Helper()
	key, err := tte2.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := tte2.NewWriter(&buf, key, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(plain)
	meta, err := tte2.SealMetadata(key, 0, tte2.Metadata{
		Index: 0, Count: 1, Name: "isolation-secret-plans.pdf", Type: "application/pdf", Size: int64(len(plain)), SHA256: hexOf(sum[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	msg, err := tte2.SealMessage(key, "isolation secret message")
	if err != nil {
		t.Fatal(err)
	}
	req := map[string]any{
		"recipients": []string{"erin@customer.example.net"}, "expiryDays": 1, "endToEndEncrypted": true, "encryptedMessage": msg,
		"files": []map[string]any{{"name": "file-1.tte2", "size": buf.Len(), "encryptedMetadata": meta}},
	}
	b, _ := json.Marshal(req)
	return string(b), e2eFixture{ciphertext: buf.Bytes(), sealedMeta: meta, sealedMsg: msg}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}

// allowE2EOnA lets tenant A's senders encrypt, as its super admin does.
func (h *harness) allowE2EOnA(t *testing.T) {
	t.Helper()
	resp := h.adminCall(t, h.superSession(t), http.MethodPatch, tenantPath(h.tenantA.ID, ""), `{"e2ePolicy":"allowed"}`)
	if resp.status != http.StatusOK || !strings.Contains(string(resp.body), `"e2ePolicy":"allowed"`) {
		t.Fatalf("super admin e2ePolicy on A: %d %s", resp.status, resp.body)
	}
}

// e2eTransferA creates an encrypted transfer as c (a sender of A) and
// uploads its ciphertext through the API. With finish, it then releases the
// transfer in the database as the finalization and the antivirus worker
// would (the server is running: no finalization through the API), and
// returns the download token.
func (h *harness) e2eTransferA(t *testing.T, c client, finish bool) e2eFixture {
	t.Helper()
	body, f := e2eCreateBody(t, []byte("plans of the acquisition, in a small encrypted file"))
	header := http.Header{}
	for kv := c.headers("Content-Type", "application/json"); len(kv) > 1; kv = kv[2:] {
		header.Set(kv[0], kv[1])
	}
	resp := h.do(t, http.MethodPost, "http://"+h.addr+"/api/v1/transfers", hostA, strings.NewReader(body), header)
	var tr createdTransfer
	var full struct {
		Files []struct {
			ID string `json:"id"`
		} `json:"files"`
	}
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &tr) != nil || json.Unmarshal(resp.body, &full) != nil || len(full.Files) != 1 {
		t.Fatalf("create an encrypted transfer under %s: %d %s", hostA, resp.status, resp.body)
	}
	f.trfID, f.fileID, f.uploadID = tr.ID, full.Files[0].ID, tr.uploadID()
	if !finish {
		return f
	}
	tus := c.headers("Tus-Resumable", "1.0.0", "Upload-Offset", "0", "Content-Type", "application/offset+octet-stream")
	up := h.call(t, opPatchUpload, hostA, map[string]string{"uploadId": f.uploadID}, string(f.ciphertext), tus...)
	if up.status != http.StatusNoContent {
		t.Fatalf("upload the ciphertext: %d %s", up.status, up.body)
	}

	ctx := context.Background()
	db, err := store.Open(ctx, h.engine.Config())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	kr, err := masterkey.New(masterkeytest.Key(t, masterKeyLabel), nil)
	if err != nil {
		t.Fatal(err)
	}
	vault := masterkey.NewVault(db, kr, nil)
	f.token, err = id.NewDownloadToken()
	if err != nil {
		t.Fatal(err)
	}
	s, err := db.Scoped(h.tenantA.ID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		if _, err := db.Transfers().FinalizeE2ETx(ctx, tx, f.trfID, now); err != nil {
			return err
		}
		wkID, err := vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte(f.token))
		if err != nil {
			return err
		}
		hash := sha256.Sum256([]byte(f.token))
		_, err = db.Transfers().MarkAvailableLinksTx(ctx, tx, f.trfID, []store.LinkToken{{Hash: hash[:], KeyID: wkID}}, now)
		return err
	})
	if err != nil {
		t.Fatalf("make the encrypted transfer available: %v", err)
	}
	return f
}

// notFoundForTus asserts a bodyless tus 404 under host and no leak.
func notFoundForTus(t *testing.T, _ *harness, op operation, host string, resp response) {
	t.Helper()
	if resp.status != http.StatusNotFound {
		t.Errorf("%s under %s: %d %q, want 404", op, host, resp.status, resp.body)
	}
	if len(resp.body) != 0 {
		t.Errorf("%s under %s: a body on a tus 404: %q", op, host, resp.body)
	}
}

// TestE2ETransferIsolation: the download, view, upload and administration
// endpoints never tell a foreign tenant, nor a foreign sender, anything of
// an encrypted transfer of tenant A.
func TestE2ETransferIsolation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		h := startHarness(t, e)
		h.allowE2EOnA(t)
		colleague := h.colleague(t)
		owner := h.owner(t)
		other := h.other(t)
		f := h.e2eTransferA(t, colleague, true)
		secrets := []string{f.sealedMeta, f.sealedMsg, "isolation-secret-plans", "isolation secret message"}
		noSecrets := func(what string, resp response) {
			t.Helper()
			for _, s := range secrets {
				if strings.Contains(string(resp.body), s) {
					t.Errorf("%s leaks %q: %s", what, s, resp.body)
				}
			}
			if bytes.Contains(resp.body, f.ciphertext[:32]) {
				t.Errorf("%s leaks the ciphertext", what)
			}
		}

		t.Run("public view", func(t *testing.T) {
			params := map[string]string{"linkToken": f.token}
			a := h.call(t, opGetDownload, hostA, params, "")
			var v struct {
				E2E     bool   `json:"endToEndEncrypted"`
				Message string `json:"encryptedMessage"`
				Archive string `json:"archiveUrl"`
				Files   []struct {
					ID   string `json:"id"`
					Name string `json:"name"`
					Meta string `json:"encryptedMetadata"`
				} `json:"files"`
			}
			if a.status != http.StatusOK || json.Unmarshal(a.body, &v) != nil || !v.E2E || v.Message != f.sealedMsg || v.Archive != "" ||
				len(v.Files) != 1 || v.Files[0].Meta != f.sealedMeta || v.Files[0].Name != "file-1.tte2" {
				t.Fatalf("%s under %s: %d %s, want the encrypted view", opGetDownload, hostA, a.status, a.body)
			}
			b := h.call(t, opGetDownload, hostB, params, "")
			refusedUnderB(t, h, opGetDownload, b, http.StatusNotFound, "not-found")
			noSecrets("getDownload under B", b)
		})

		t.Run("file", func(t *testing.T) {
			params := map[string]string{"linkToken": f.token, "fileId": f.fileID}
			a := h.call(t, opDownloadOne, hostA, params, "")
			if a.status != http.StatusOK || !bytes.Equal(a.body, f.ciphertext) {
				t.Fatalf("%s under %s: %d (%d bytes), want the ciphertext", opDownloadOne, hostA, a.status, len(a.body))
			}
			b := h.call(t, opDownloadOne, hostB, params, "")
			refusedUnderB(t, h, opDownloadOne, b, http.StatusNotFound, "not-found")
			// A byte range is no way around it either.
			r := h.call(t, opDownloadOne, hostB, params, "", "Range", "bytes=0-31")
			refusedUnderB(t, h, opDownloadOne, r, http.StatusNotFound, "not-found")
		})

		t.Run("archive", func(t *testing.T) {
			// Under A the encrypted transfer has no archive (409); under B the
			// answer must not tell that it exists, nor what it is (T-324).
			params := map[string]string{"linkToken": f.token}
			wantCode(t, opArchive, hostA, h.call(t, opArchive, hostA, params, ""), http.StatusConflict, "e2e-archive-unavailable")
			refusedUnderB(t, h, opArchive, h.call(t, opArchive, hostB, params, ""), http.StatusNotFound, "not-found")
		})

		t.Run("sender endpoints", func(t *testing.T) {
			params := map[string]string{"transferId": f.trfID}
			own := h.call(t, opGetTransfer, hostA, params, "", colleague.headers()...)
			var v struct {
				E2E bool `json:"endToEndEncrypted"`
			}
			if own.status != http.StatusOK || json.Unmarshal(own.body, &v) != nil || !v.E2E {
				t.Fatalf("%s for its sender: %d %s", opGetTransfer, own.status, own.body)
			}
			for _, op := range []operation{opGetTransfer, opFinalize, opCancel} {
				a := h.call(t, op, hostA, params, "", owner.headers()...)
				wantCode(t, op, hostA, a, http.StatusNotFound, "not-found")
				noSecrets(op.id+" by another sender of A", a)
				b := h.call(t, op, hostB, params, "", other.headers()...)
				refusedUnderB(t, h, op, b, http.StatusNotFound, "not-found")
				noSecrets(op.id+" under B", b)
			}
			// The transfer is intact.
			if again := h.call(t, opGetTransfer, hostA, params, "", colleague.headers()...); again.status != http.StatusOK {
				t.Errorf("transfer after the foreign calls: %d %s", again.status, again.body)
			}
		})

		t.Run("uploads", func(t *testing.T) {
			// An encrypted upload still open: foreign senders get a bodyless 404,
			// never 400 e2e-format-invalid (an oracle on the declared stream), and
			// write nothing.
			up := h.e2eTransferA(t, colleague, false)
			params := map[string]string{"uploadId": up.uploadID}
			tus := []string{"Tus-Resumable", "1.0.0"}
			patch := append([]string{"Upload-Offset", "0", "Content-Type", "application/offset+octet-stream"}, tus...)
			garbage := strings.Repeat("plaintext, certainly not a TTE2 stream. ", 3)
			for _, c := range []client{owner, other} {
				host := c.host
				notFoundForTus(t, h, opHeadUpload, host, h.call(t, opHeadUpload, host, params, "", c.headers(tus...)...))
				notFoundForTus(t, h, opPatchUpload, host, h.call(t, opPatchUpload, host, params, garbage, c.headers(patch...)...))
				notFoundForTus(t, h, opTermUpload, host, h.call(t, opTermUpload, host, params, "", c.headers(tus...)...))
			}
			// The sender is checked, and nothing was written by the others.
			own := h.call(t, opHeadUpload, hostA, params, "", colleague.headers(tus...)...)
			if own.status != http.StatusOK || own.header.Get("Upload-Offset") != "0" {
				t.Fatalf("%s for its sender: %d %v, want offset 0", opHeadUpload, own.status, own.header)
			}
			bad := h.call(t, opPatchUpload, hostA, params, garbage, colleague.headers(patch...)...)
			if bad.status != http.StatusBadRequest {
				t.Errorf("%s of garbage by its sender: %d %s, want 400", opPatchUpload, bad.status, bad.body)
			}
		})

		t.Run("creation and policy", func(t *testing.T) {
			// A's session cannot create under B, and B's senders do not inherit
			// A's policy: B stays forbidden by default (403 e2e-forbidden).
			body, _ := e2eCreateBody(t, []byte("under B"))
			resp := h.call(t, opCreate, hostB, nil, body, owner.headers("Content-Type", "application/json")...)
			refusedUnderB(t, h, opCreate, resp, http.StatusUnauthorized, "unauthenticated")
			resp = h.call(t, opCreate, hostB, nil, body, other.headers("Content-Type", "application/json")...)
			wantCode(t, opCreate, hostB, resp, http.StatusForbidden, "e2e-forbidden")
			noLeak(t, h, opCreate, hostB, resp)
			// The public configuration announces each tenant's own policy.
			policy := func(host string) string {
				resp := h.call(t, opPublicInfo, host, nil, "")
				var v struct {
					Features struct {
						E2EPolicy string `json:"e2ePolicy"`
					} `json:"features"`
				}
				if resp.status != http.StatusOK || json.Unmarshal(resp.body, &v) != nil {
					t.Fatalf("%s under %s: %d %s", opPublicInfo, host, resp.status, resp.body)
				}
				return v.Features.E2EPolicy
			}
			if a, b := policy(hostA), policy(hostB); a != "allowed" || b != "forbidden" {
				t.Errorf("announced policies: A %q, B %q, want allowed and forbidden", a, b)
			}
		})

		t.Run("administration", func(t *testing.T) {
			deleg := h.session(t)
			rest := "/transfers/" + f.trfID
			// The delegated admin of A reads the transfer: generic names, the
			// flag, never the sealed values; under B's path it is unknown.
			own := h.adminCall(t, deleg, http.MethodGet, tenantPath(h.tenantA.ID, rest), "")
			var v struct {
				E2E   bool `json:"endToEndEncrypted"`
				Files []struct {
					Name string `json:"name"`
				} `json:"files"`
			}
			if own.status != http.StatusOK || json.Unmarshal(own.body, &v) != nil || !v.E2E || len(v.Files) != 1 || v.Files[0].Name != "file-1.tte2" {
				t.Fatalf("getTenantTransfer by A's delegated admin: %d %s", own.status, own.body)
			}
			noSecrets("getTenantTransfer", own)
			op := operation{id: "getTenantTransfer"}
			foreign := h.adminCall(t, deleg, http.MethodGet, tenantPath(h.tenantB.ID, rest), "")
			missing := h.adminCall(t, deleg, http.MethodGet, tenantPath(tenant.ID(id.New(id.Tenant)), rest), "")
			h.sameAsMissing(t, op, foreign, missing, f.trfID)

			// The policy of a tenant is the super admin's: 403 on A, the answer of
			// an unknown tenant on B, even with an invalid value.
			up := operation{id: "updateTenant"}
			resp := h.adminCall(t, deleg, http.MethodPatch, tenantPath(h.tenantA.ID, ""), `{"e2ePolicy":"required"}`)
			wantCode(t, up, hostAdmin, resp, http.StatusForbidden, "forbidden")
			h.invalidInputOfB(t, up, deleg, http.MethodPatch, "", `{"e2ePolicy":"required"}`)
			h.invalidInputOfB(t, up, deleg, http.MethodPatch, "", `{"e2ePolicy":"sometimes"}`)
			if got := h.adminCall(t, h.superSession(t), http.MethodGet, tenantPath(h.tenantA.ID, ""), ""); !strings.Contains(string(got.body), `"e2ePolicy":"allowed"`) {
				t.Errorf("tenant A policy after the refused changes: %s", got.body)
			}
			if got := h.adminCall(t, h.superSession(t), http.MethodGet, tenantPath(h.tenantB.ID, ""), ""); !strings.Contains(string(got.body), `"e2ePolicy":"forbidden"`) {
				t.Errorf("tenant B policy after the refused changes: %s", got.body)
			}

			// A level policy is written by the delegated admin of A on A, and on
			// B's path it is the answer of an unknown tenant, nothing is written.
			levels := `{"items":[{"key":"isoe2e","labels":{"en":"Iso","fr":"Iso"},"isDefault":true,"rules":{"requireRecipientVerification":false,` +
				`"requirePassword":false,"allowedExpiryDays":[1],"internalRecipientsOnly":false,"forceDeleteAfterFirstDownload":false,` +
				`"maxDownloads":null,"e2ePolicy":"required"}}]}`
			lv := operation{id: "updateConfidentialityLevels"}
			if r := h.adminCall(t, deleg, http.MethodPut, tenantPath(h.tenantA.ID, "/confidentiality-levels"), levels); r.status != http.StatusOK {
				t.Fatalf("delegated admin level policy on A: %d %s", r.status, r.body)
			}
			h.invalidInputOfB(t, lv, deleg, http.MethodPut, "/confidentiality-levels", levels)
			if got := h.adminCall(t, h.superSession(t), http.MethodGet, tenantPath(h.tenantB.ID, "/confidentiality-levels"), ""); strings.Contains(string(got.body), "isoe2e") {
				t.Errorf("tenant B levels hold the level written for A: %s", got.body)
			}
		})
	})
}
