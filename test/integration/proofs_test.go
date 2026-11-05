package integration_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/proof"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// Integration tests of the sealed proofs of deposit and delivery (CLAUDE.md
// section 22; api/openapi.yaml getMyTransferProof, getTenantTransferProof,
// listProofKeys; threat model 6.49, T-298 to T-303).

const (
	pathProofKeys = "/api/v1/proof-keys"
	// proofVerifyLimit bounds the size of a PDF read by proof.Verify.
	proofVerifyLimit = 8 << 20
	actProofDownload = "transfer.proof_downloaded"
)

// meSessionOf opens a "My transfers" session of email in tenant A, through
// the API, from an access link stored directly in the database (the mail
// that carries it is not under test) and returns the headers that carry it.
func (d *depositEnv) meSessionOf(t *testing.T, email string) http.Header {
	t.Helper()
	token, err := id.NewToken(id.AccessLinkTokenPrefix, id.AccessLinkTokenBytes)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(token))
	now := time.Now().UTC().Truncate(time.Millisecond)
	if _, err := d.db.SenderAccess().CreateLink(t.Context(), d.tenantA.ID, hash[:], email, now, now.Add(15*time.Minute)); err != nil {
		t.Fatalf("create access link: %v", err)
	}
	resp := d.do(t, request{
		method: http.MethodPost, path: "/api/v1/me/sessions", host: hostA, body: []byte(`{"token":"` + token + `"}`),
		headers: http.Header{hdrXFF: {insideA}, "Content-Type": {contentJSON}},
	})
	var s struct {
		CSRFToken string `json:"csrfToken"`
	}
	if resp.status != http.StatusCreated {
		t.Fatalf("start my transfers session: %d %s", resp.status, resp.body)
	}
	mustJSON(t, resp.body, &s)
	for _, c := range (&http.Response{Header: resp.header}).Cookies() {
		if c.Name == "__Host-tt_me" {
			return http.Header{hdrXFF: {insideA}, "Cookie": {c.Name + "=" + c.Value}, hdrCSRF: {s.CSRFToken}}
		}
	}
	t.Fatalf("my transfers session set no cookie: %v", resp.header)
	return nil
}

// proofKeys reads the public keys of GET /proof-keys under host.
func (d *depositEnv) proofKeys(t *testing.T, host string) []proof.PublicKey {
	t.Helper()
	resp := d.do(t, request{method: http.MethodGet, path: pathProofKeys, host: host})
	expectContract(t, "listProofKeys", http.MethodGet, pathProofKeys, resp)
	if resp.status != http.StatusOK {
		t.Fatalf("listProofKeys under %s: %d %s", host, resp.status, resp.body)
	}
	var list struct {
		Items []struct {
			KeyID     string  `json:"keyId"`
			Algorithm string  `json:"algorithm"`
			PublicKey string  `json:"publicKey"`
			CreatedAt string  `json:"createdAt"`
			RetiredAt *string `json:"retiredAt"`
		} `json:"items"`
	}
	mustJSON(t, resp.body, &list)
	var keys []proof.PublicKey
	for _, it := range list.Items {
		raw, err := base64.RawURLEncoding.DecodeString(it.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize || it.Algorithm != "Ed25519" {
			t.Fatalf("key %+v is not an Ed25519 public key (%v)", it, err)
		}
		created, err := time.Parse(time.RFC3339, it.CreatedAt)
		if err != nil {
			t.Fatal(err)
		}
		k := proof.PublicKey{KeyID: it.KeyID, PublicKey: raw, CreatedAt: created}
		if it.RetiredAt != nil {
			if k.RetiredAt, err = time.Parse(time.RFC3339, *it.RetiredAt); err != nil {
				t.Fatal(err)
			}
		}
		keys = append(keys, k)
	}
	return keys
}

// expectProofPDF checks the headers of a 200 proof answer and verifies the
// PDF it carries against keys; it returns the verified statement.
func expectProofPDF(t *testing.T, what string, resp response, keys []proof.PublicKey) proof.Statement {
	t.Helper()
	if resp.status != http.StatusOK {
		t.Fatalf("%s: %d %s", what, resp.status, resp.body)
	}
	if ct := resp.header.Get("Content-Type"); ct != "application/pdf" {
		t.Errorf("%s: Content-Type %q", what, ct)
	}
	if cd := resp.header.Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
		t.Errorf("%s: Content-Disposition %q", what, cd)
	}
	if cc := resp.header.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("%s: Cache-Control %q", what, cc)
	}
	if resp.header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("%s: X-Content-Type-Options %q", what, resp.header.Get("X-Content-Type-Options"))
	}
	if !bytes.HasPrefix(resp.body, []byte("%PDF-")) {
		t.Fatalf("%s: not a PDF", what)
	}
	st, err := proof.Verify(bytes.NewReader(resp.body), keys, proofVerifyLimit)
	if err != nil {
		t.Fatalf("%s: verification failed: %v", what, err)
	}
	return st
}

// expectProofNotAvailable checks a 404 proof-not-available answer.
func expectProofNotAvailable(t *testing.T, what string, resp response) {
	t.Helper()
	if resp.status != http.StatusNotFound {
		t.Fatalf("%s: %d %s, want 404", what, resp.status, resp.body)
	}
	var p struct {
		Code string `json:"code"`
	}
	mustJSON(t, resp.body, &p)
	if p.Code != "proof-not-available" {
		t.Errorf("%s: code %q, want proof-not-available", what, p.Code)
	}
}

// TestProofsFlow follows the proofs through a whole life of a transfer:
// the deposit proof once the antivirus released it, the delivery proofs at
// the first downloads, each verified offline with the published keys, the
// proofs outliving the deletion of the transfer, and their erasure with the
// sender.
func TestProofsFlow(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		alice, sender := internalSession(t, o.depositEnv, "alice")
		r1, r2 := uniqueEmail(t, "proof-one", "example.net"), uniqueEmail(t, "proof-two", "example.org")
		content := []byte("content sealed by a proof")
		tr, _ := alice.availableTransfer(t, transferCreate{Recipients: []string{r1, r2}}, uploadedFile{"sealed.txt", content})
		me := o.meSessionOf(t, sender)
		keys := o.proofKeys(t, hostA)
		if len(keys) != 1 || !keys[0].RetiredAt.IsZero() {
			t.Fatalf("keys = %+v, want one active key", keys)
		}
		if admKeys := o.proofKeys(t, adminHost); len(admKeys) != 1 || admKeys[0].KeyID != keys[0].KeyID {
			t.Errorf("keys under the admin host = %+v", admKeys)
		}
		path := func(kind string, recipient string) string {
			q := url.Values{"kind": {kind}}
			if recipient != "" {
				q.Set("recipient", recipient)
			}
			return "/api/v1/me/transfers/" + tr.ID + "/proof?" + q.Encode()
		}
		adminPath := func(kind string, recipient string) string {
			q := url.Values{"kind": {kind}}
			if recipient != "" {
				q.Set("recipient", recipient)
			}
			return tenantPath(o.tid, "/transfers/"+tr.ID+"/proof?"+q.Encode())
		}
		getMe := func(kind, recipient string) response {
			resp := o.do(t, request{method: http.MethodGet, path: path(kind, recipient), host: hostA, headers: me})
			expectContract(t, "getMyTransferProof", http.MethodGet, path(kind, recipient), resp)
			return resp
		}
		getAdmin := func(kind, recipient string) response {
			resp := o.sa.call(t, http.MethodGet, adminPath(kind, recipient), nil)
			expectContract(t, "getTenantTransferProof", http.MethodGet, adminPath(kind, recipient), resp)
			return resp
		}

		// Deposit: written when the antivirus released the transfer.
		deposit := getMe("deposit", "")
		st := expectProofPDF(t, "my deposit proof", deposit, keys)
		if st.Kind != store.ProofDeposit || st.TransferID != tr.ID || st.SenderEmail != sender || st.KeyID != keys[0].KeyID ||
			st.FirstDownloadedAt != nil || len(st.Recipients) != 2 || len(st.Files) != 1 ||
			st.Files[0].Name != "sealed.txt" || st.Files[0].SHA256 != sha256Hex(content) || st.Files[0].Size != int64(len(content)) ||
			st.Files[0].ScanStatus != "clean" || st.Tenant.FQDN != hostA {
			t.Errorf("deposit statement = %+v", st)
		}
		adminDeposit := getAdmin("deposit", "")
		if st2 := expectProofPDF(t, "admin deposit proof", adminDeposit, keys); st2.TransferID != tr.ID || st2.KeyID != st.KeyID ||
			st2.DepositedAt != st.DepositedAt {
			t.Errorf("admin deposit statement = %+v", st2)
		}

		// Delivery: nothing before the first download.
		expectProofNotAvailable(t, "delivery before any download", getMe("delivery", ""))
		expectProofNotAvailable(t, "recipient delivery before any download", getMe("delivery", r1))

		// The first recipient downloads: the overall delivery and theirs.
		token1 := tokenOf(t, hostA, o.recipientLink(t, hostA, tr.ID, r1))
		o.secret(token1)
		expectFile(t, "download by r1", o.newRecipient(1).get(t, filePath(token1, tr.Files[0].ID), nil), "sealed.txt", content)
		delivery := expectProofPDF(t, "my delivery proof", getMe("delivery", ""), keys)
		if delivery.Kind != store.ProofDelivery || delivery.FirstDownloadedAt == nil || len(delivery.RecipientDownloads) != 1 ||
			delivery.RecipientDownloads[0].Email != r1 || delivery.TransferID != tr.ID {
			t.Errorf("delivery statement = %+v", delivery)
		}
		mine := expectProofPDF(t, "my delivery proof of r1", getMe("delivery", r1), keys)
		if len(mine.RecipientDownloads) != 1 || mine.RecipientDownloads[0].Email != r1 {
			t.Errorf("recipient delivery statement = %+v", mine)
		}
		// r2 has not downloaded, and a stranger is no recipient.
		expectProofNotAvailable(t, "delivery of r2", getMe("delivery", r2))
		expectProofNotAvailable(t, "delivery of a stranger", getMe("delivery", uniqueEmail(t, "stranger", "example.com")))
		if resp := getMe("delivery", "not an address"); resp.status != http.StatusNotFound && resp.status != http.StatusBadRequest {
			t.Errorf("delivery of a malformed address: %d %s", resp.status, resp.body)
		}
		// The recipient of a deposit proof makes no sense.
		if resp := getMe("deposit", r1); resp.status != http.StatusBadRequest {
			t.Errorf("deposit with a recipient: %d %s, want 400", resp.status, resp.body)
		}

		// The second recipient downloads: their own proof appears.
		token2 := tokenOf(t, hostA, o.recipientLink(t, hostA, tr.ID, r2))
		o.secret(token2)
		expectFile(t, "download by r2", o.newRecipient(2).get(t, filePath(token2, tr.Files[0].ID), nil), "sealed.txt", content)
		if st := expectProofPDF(t, "admin delivery proof of r2", getAdmin("delivery", r2), keys); len(st.RecipientDownloads) != 1 ||
			st.RecipientDownloads[0].Email != r2 {
			t.Errorf("admin recipient delivery statement = %+v", st)
		}
		// The overall proof is immutable: it is still the one of the first download.
		if again := expectProofPDF(t, "my delivery proof again", getMe("delivery", ""), keys); *again.FirstDownloadedAt != *delivery.FirstDownloadedAt ||
			len(again.RecipientDownloads) != 1 {
			t.Errorf("overall delivery changed: %+v", again)
		}

		// A byte of the signed statement changed: the verification fails.
		tampered := bytes.Clone(deposit.body)
		marker := []byte(`"senderEmail":"`)
		i := bytes.Index(tampered, marker)
		if i < 0 {
			t.Fatal("statement.json not found in the PDF")
		}
		tampered[i+len(marker)] ^= 0x01 // the first letter of the sender address
		if _, err := proof.Verify(bytes.NewReader(tampered), keys, proofVerifyLimit); !errors.Is(err, proof.ErrBadSignature) {
			t.Errorf("tampered proof: %v, want ErrBadSignature", err)
		}
		// A PDF verified with no key of the instance is refused as well.
		if _, err := proof.Verify(bytes.NewReader(deposit.body), nil, proofVerifyLimit); !errors.Is(err, proof.ErrUnknownKey) {
			t.Errorf("proof without keys: %v, want ErrUnknownKey", err)
		}

		// Every download is audited with its kind, without the address.
		events := o.sa.tenantEvents(t, o.tid, actProofDownload)
		if len(events) != 6 {
			t.Errorf("%d %s events, want 6", len(events), actProofDownload)
		}
		for _, ev := range events {
			expectNoAddressIn(t, ev)
		}

		// The data subject search counts the proofs naming the sender.
		var sum struct {
			Proofs *int `json:"proofs"`
		}
		resp := mustStatus(t, "searchDataSubject", o.sa.call(t, http.MethodPost, tenantPath(o.tid, "/data-subjects/search"),
			map[string]string{"email": sender}), http.StatusOK)
		mustJSON(t, resp.body, &sum)
		// Deposit, overall delivery and the two recipient deliveries.
		if sum.Proofs == nil || *sum.Proofs != 4 {
			t.Errorf("data subject summary proofs = %v, want 4", sum.Proofs)
		}

		// The transfer is deleted: the sender no longer sees it, while the
		// proofs, which outlive it, stay available to the admins.
		mustStatus(t, "deleteTenantTransfer", o.sa.deleteTransfer(t, o.tid, tr.ID, "test"), http.StatusNoContent)
		if resp := getMe("deposit", ""); resp.status != http.StatusNotFound {
			t.Errorf("sender proof of a deleted transfer: %d %s, want 404", resp.status, resp.body)
		}
		if st := expectProofPDF(t, "admin proof of a deleted transfer", getAdmin("deposit", ""), keys); st.TransferID != tr.ID {
			t.Errorf("statement after deletion = %+v", st)
		}
		expectProofPDF(t, "admin delivery of a deleted transfer", getAdmin("delivery", ""), keys)

		// The erasure of the sender deletes the proofs that name them.
		erase := mustStatus(t, "eraseDataSubject", o.sa.eraseSubject(t, o.tid, sender), http.StatusOK)
		var rep struct {
			ProofsDeleted *int `json:"proofsDeleted"`
		}
		mustJSON(t, erase.body, &rep)
		if rep.ProofsDeleted == nil || *rep.ProofsDeleted != 4 {
			t.Errorf("erase report proofsDeleted = %v, want 4", rep.ProofsDeleted)
		}
		for _, kind := range []string{"deposit", "delivery"} {
			expectProofNotAvailable(t, "admin "+kind+" proof after the erasure", getAdmin(kind, ""))
		}
		expectProofNotAvailable(t, "admin proof of r2 after the erasure", getAdmin("delivery", r2))
		var left struct {
			Items []json.RawMessage `json:"items"`
		}
		mustJSON(t, o.do(t, request{method: http.MethodGet, path: pathProofKeys, host: hostA}).body, &left)
		if len(left.Items) != 1 {
			t.Errorf("the erasure removed signing keys: %d left", len(left.Items))
		}
	})
}

// TestContractHarnessCoversProofs checks that the contract validator is not
// vacuous for the PDF operations: a wrong content type and an undeclared
// status are reported, a valid answer is
// accepted.
func TestContractHarnessCoversProofs(t *testing.T) {
	t.Parallel()
	const path = "/api/v1/me/transfers/trf_01JAB00000000000000000TRFA/proof?kind=deposit"
	headers := func() http.Header {
		return http.Header{
			"Content-Type": {"application/pdf"}, "Content-Disposition": {`attachment; filename="proof.pdf"`},
			"Cache-Control": {"no-store"}, "X-Content-Type-Options": {"nosniff"},
		}
	}
	if err := contractError(t, "getMyTransferProof", http.MethodGet, path, response{status: 200, header: headers(), body: []byte("%PDF-1.7")}); err != nil {
		t.Errorf("a valid PDF answer is refused: %v", err)
	}
	wrong := headers()
	wrong.Set("Content-Type", "text/html")
	for name, resp := range map[string]response{
		"wrong content type": {status: 200, header: wrong, body: []byte("<html>")},
		"undeclared status":  {status: 418, header: headers(), body: []byte("x")},
	} {
		if contractError(t, "getMyTransferProof", http.MethodGet, path, resp) == nil {
			t.Errorf("%s: the violation was not detected", name)
		}
	}
}
