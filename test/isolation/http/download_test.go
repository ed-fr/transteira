package httpisolation_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/download"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/store"
)

// downloadPassword protects the transfers of the download cases.
const downloadPassword = "correct horse battery staple"

// availableDownloadA creates, as tenant A's owner, a password-protected
// transfer of one empty file (complete at creation), then makes it
// available directly in the database, as the antivirus would, and returns
// its download token. The transfer is never handed to the antivirus of the
// server (no finalization through the API, no sweep: the server is already
// running).
func (h *harness) availableDownloadA(t *testing.T) string {
	t.Helper()
	o := h.owner(t)
	header := http.Header{}
	for kv := o.headers("Content-Type", "application/json"); len(kv) > 1; kv = kv[2:] {
		header.Set(kv[0], kv[1])
	}
	body := `{"recipients":["erin@customer.example.net"],"expiryDays":1,"password":"` + downloadPassword +
		`","files":[{"name":"empty.txt","size":0}]}`
	resp := h.do(t, http.MethodPost, "http://"+h.addr+"/api/v1/transfers", hostA, strings.NewReader(body), header)
	var tr struct {
		ID    string `json:"id"`
		Files []struct {
			ID string `json:"id"`
		} `json:"files"`
	}
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &tr) != nil || len(tr.Files) != 1 {
		t.Fatalf("create transfer: %d %s", resp.status, resp.body)
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
	token, err := id.NewDownloadToken()
	if err != nil {
		t.Fatal(err)
	}
	s, err := db.Scoped(h.tenantA.ID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	err = s.Tx(ctx, func(tx *store.ScopedTx) error {
		if err := db.Transfers().FinalizeTx(ctx, tx, tr.ID, now); err != nil {
			return err
		}
		if err := db.TransferFiles().SetScanResultTx(ctx, tx, tr.Files[0].ID, store.ScanClean, "", now); err != nil {
			return err
		}
		wkID, err := vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte(token))
		if err != nil {
			return err
		}
		hash := sha256.Sum256([]byte(token))
		return db.Transfers().MarkAvailableTx(ctx, tx, tr.ID, hash[:], wkID, now)
	})
	if err != nil {
		t.Fatalf("make the transfer available: %v", err)
	}
	return token
}

// unlockA unlocks token under tenant A with the right password and returns
// the grant cookie.
func (h *harness) unlockA(t *testing.T, op operation, token string) string {
	t.Helper()
	resp := h.call(t, op, hostA, map[string]string{"linkToken": token}, `{"password":"`+downloadPassword+`"}`)
	if resp.status != http.StatusNoContent {
		t.Fatalf("unlock under %s: %d %s", hostA, resp.status, resp.body)
	}
	for _, c := range (&http.Response{Header: resp.header}).Cookies() {
		if c.Name == download.GrantCookieName {
			return c.Value
		}
	}
	t.Fatalf("unlock under %s set no grant cookie: %v", hostA, resp.header)
	return ""
}

// unlockOp is the unlockDownload operation, for the cases of the other
// download operations that need a grant.
func unlockOp() operation {
	return operation{id: "unlockDownload", verb: http.MethodPost, template: "/downloads/{linkToken}/unlock", base: "/api/v1"}
}

// getForeignDownload: A's link shows A's (locked) page under A, and is
// unknown under B.
func getForeignDownload(t *testing.T, h *harness, op operation) {
	t.Helper()
	token := h.availableDownloadA(t)
	params := map[string]string{"linkToken": token}
	a := h.call(t, op, hostA, params, "")
	if a.status != http.StatusOK || !strings.Contains(string(a.body), `"locked":true`) {
		t.Fatalf("%s under %s: %d %s, want the locked page", op, hostA, a.status, a.body)
	}
	grant := h.unlockA(t, unlockOp(), token)
	refusedUnderB(t, h, op, h.call(t, op, hostB, params, "", "Cookie", download.GrantCookieName+"="+grant), http.StatusNotFound, "not-found")
}

// unlockForeignDownload: wrong passwords under B are refused as unknown
// (404) and never count against A's transfer: under A, the first wrong
// password still leaves 2 attempts, and the right one unlocks.
func unlockForeignDownload(t *testing.T, h *harness, op operation) {
	t.Helper()
	token := h.availableDownloadA(t)
	params := map[string]string{"linkToken": token}
	for range 4 {
		refusedUnderB(t, h, op, h.call(t, op, hostB, params, `{"password":"wrong"}`), http.StatusNotFound, "not-found")
	}
	resp := h.call(t, op, hostA, params, `{"password":"wrong"}`)
	var p struct {
		Code              string `json:"code"`
		AttemptsRemaining *int   `json:"attemptsRemaining"`
	}
	_ = json.Unmarshal(resp.body, &p)
	if resp.status != http.StatusUnauthorized || p.Code != "transfer-password-invalid" || p.AttemptsRemaining == nil || *p.AttemptsRemaining != 2 {
		t.Fatalf("first wrong password under %s: %d %s, want 401 with 2 attempts left", hostA, resp.status, resp.body)
	}
	h.unlockA(t, op, token)
}

// fileOfForeignDownload: A's file, with A's grant, is unknown under B; under
// A without grant it is locked, and with the grant it is served.
func fileOfForeignDownload(t *testing.T, h *harness, op operation) {
	t.Helper()
	token := h.availableDownloadA(t)
	page := h.call(t, operation{id: "getDownload", verb: http.MethodGet, template: "/downloads/{linkToken}", base: "/api/v1"},
		hostA, map[string]string{"linkToken": token}, "", "Cookie", download.GrantCookieName+"="+h.unlockA(t, unlockOp(), token))
	var v struct {
		Files []struct {
			ID string `json:"id"`
		} `json:"files"`
	}
	if page.status != http.StatusOK || json.Unmarshal(page.body, &v) != nil || len(v.Files) != 1 {
		t.Fatalf("unlocked page under %s: %d %s", hostA, page.status, page.body)
	}
	params := map[string]string{"linkToken": token, "fileId": v.Files[0].ID}
	grant := h.unlockA(t, unlockOp(), token)
	cookie := []string{"Cookie", download.GrantCookieName + "=" + grant}
	wantCode(t, op, hostA, h.call(t, op, hostA, params, ""), http.StatusUnauthorized, "download-locked")
	if a := h.call(t, op, hostA, params, "", cookie...); a.status != http.StatusOK || a.header.Get("Content-Security-Policy") != "default-src 'none'; sandbox; frame-ancestors 'none'" {
		t.Fatalf("%s under %s with the grant: %d %v", op, hostA, a.status, a.header)
	}
	refusedUnderB(t, h, op, h.call(t, op, hostB, params, "", cookie...), http.StatusNotFound, "not-found")
}

// archiveOfForeignDownload: A's archive, with A's grant, is unknown under
// B; under A without grant it is locked, and with the grant it is served.
func archiveOfForeignDownload(t *testing.T, h *harness, op operation) {
	t.Helper()
	token := h.availableDownloadA(t)
	params := map[string]string{"linkToken": token}
	cookie := []string{"Cookie", download.GrantCookieName + "=" + h.unlockA(t, unlockOp(), token)}
	wantCode(t, op, hostA, h.call(t, op, hostA, params, ""), http.StatusUnauthorized, "download-locked")
	if a := h.call(t, op, hostA, params, "", cookie...); a.status != http.StatusOK || a.header.Get("Content-Type") != "application/zip" {
		t.Fatalf("%s under %s with the grant: %d %v", op, hostA, a.status, a.header)
	}
	refusedUnderB(t, h, op, h.call(t, op, hostB, params, "", cookie...), http.StatusNotFound, "not-found")
}
