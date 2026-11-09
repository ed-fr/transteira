package httpisolation_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tte2"
)

// The one-time secrets (since 2.1). Step 2 checks, per operation, that a
// secret of tenant A is never reached under tenant B's host; the complete
// authenticated suite (API tokens, invited externals, admin operations)
// comes with wave 3.

// sealedSecret is a secret sealed as a browser would, without passphrase.
type sealedSecret struct {
	text, verifier, keyVerifier, keyProof, proof string
}

// sealSecret seals text with a new key.
func sealSecret(t *testing.T, text string) sealedSecret {
	t.Helper()
	key, err := tte2.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	root, err := tte2.DeriveSecretKey(key, "", tte2.PassphraseDescriptor{})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := tte2.SealSecret(root, text)
	if err != nil {
		t.Fatal(err)
	}
	keyProof, _ := tte2.SecretKeyProof(key)
	proof, _ := tte2.SecretProof(root)
	return sealedSecret{
		text: sealed, keyProof: tte2.EncodeProof(keyProof), proof: tte2.EncodeProof(proof),
		verifier: tte2.EncodeProof(tte2.SecretVerifier(proof)), keyVerifier: tte2.EncodeProof(tte2.SecretVerifier(keyProof)),
	}
}

// createBody is the creation body of s (link delivery, one day).
func (s sealedSecret) createBody() string {
	return `{"encryptedText":"` + s.text + `","verifier":"` + s.verifier + `","keyVerifier":"` + s.keyVerifier +
		`","expiresIn":"1d","delivery":"link"}`
}

// revealBody is the reveal body of s.
func (s sealedSecret) revealBody() string {
	return `{"keyProof":"` + s.keyProof + `","proof":"` + s.proof + `"}`
}

// createdSecretA is a secret of tenant A created by its owner (insiderA).
type createdSecretA struct {
	sealedSecret
	ID    string `json:"id"`
	Token string `json:"token"`
}

// opCreateSecret is the createSecret operation.
var opCreateSecret = operation{id: "createSecret", verb: http.MethodPost, template: "/secrets", base: "/api/v1"}

// createSecretA creates, through the API under A, a secret of A's owner.
func (h *harness) createSecretA(t *testing.T) createdSecretA {
	t.Helper()
	s := createdSecretA{sealedSecret: sealSecret(t, "isolation one-time secret")}
	resp := h.call(t, opCreateSecret, hostA, nil, s.createBody(), h.owner(t).headers()...)
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &s) != nil || s.ID == "" || s.Token == "" {
		t.Fatalf("create secret under %s: %d %s", hostA, resp.status, resp.body)
	}
	return s
}

// noSealed asserts resp holds nothing of the secret s.
func noSealed(t *testing.T, h *harness, op operation, host string, resp response, s createdSecretA) {
	t.Helper()
	noLeak(t, h, op, host, resp)
	for _, v := range []string{s.text, s.Token, s.verifier, s.keyVerifier, insiderA} {
		if strings.Contains(string(resp.body), v) {
			t.Errorf("%s under %s leaks a value of A's secret: %s", op, host, resp.body)
		}
	}
}

// createSecretWithForeignSession: A's session creates under A and is
// unauthenticated under B.
func createSecretWithForeignSession(t *testing.T, h *harness, op operation) {
	t.Helper()
	h.createSecretA(t)
	body := sealSecret(t, "under B").createBody()
	refusedUnderB(t, h, op, h.call(t, op, hostB, nil, body, h.owner(t).headers()...), http.StatusUnauthorized, "unauthenticated")
	// B's session is unknown under A, and each tenant's API token creates
	// under its own host only.
	resp := h.call(t, op, hostA, nil, body, h.other(t).headers()...)
	wantCode(t, op, hostA, resp, http.StatusUnauthorized, "unauthenticated")
	noLeak(t, h, op, hostA, resp)
	tokA, tokB := h.openTokenOf(t, op, h.tenantA.ID), h.openTokenOf(t, op, h.tenantB.ID)
	for _, c := range []struct {
		host, token, sender string
		ok                  bool
	}{
		{hostA, tokA, insiderA, true},
		{hostB, tokB, insiderB, true},
		{hostB, tokA, insiderB, false},
		{hostA, tokB, insiderA, false},
	} {
		// A token deposit names its sender, an address of the tenant.
		tokenBody := strings.Replace(body, `{`, `{"senderEmail":"`+c.sender+`",`, 1)
		resp := h.call(t, op, c.host, nil, tokenBody, "Authorization", "Bearer "+c.token)
		if c.ok {
			if resp.status != http.StatusCreated {
				t.Errorf("%s under %s with its own API token: %d %s, want 201", op, c.host, resp.status, resp.body)
			}
			continue
		}
		wantCode(t, op, c.host, resp, http.StatusUnauthorized, "invalid-credentials")
		noLeak(t, h, op, c.host, resp)
	}
}

// openTokenOf creates, as the super admin, an API token of tenant tid
// without address restriction and returns its secret.
func (h *harness) openTokenOf(t *testing.T, op operation, tid tenant.ID) string {
	t.Helper()
	resp := h.adminCall(t, h.superSession(t), http.MethodPost, tenantPath(tid, "/api-tokens"),
		`{"name":"Secrets token","allowedCidrs":["0.0.0.0/0","::/0"]}`)
	var tok apiTokenView
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &tok) != nil || tok.Token == "" {
		t.Fatalf("%s: create an API token of %s: %d %s", op, tid, resp.status, resp.body)
	}
	return tok.Token
}

// getForeignSecretLink: A's token is active under A and unknown under B.
func getForeignSecretLink(t *testing.T, h *harness, op operation) {
	t.Helper()
	s := h.createSecretA(t)
	params := map[string]string{"secretToken": s.Token}
	if resp := h.call(t, op, hostA, params, ""); resp.status != http.StatusOK || !strings.Contains(string(resp.body), `"state":"active"`) {
		t.Fatalf("%s under %s: %d %s", op, hostA, resp.status, resp.body)
	}
	resp := h.call(t, op, hostB, params, "")
	wantCode(t, op, hostB, resp, http.StatusNotFound, "not-found")
	noSealed(t, h, op, hostB, resp, s)
}

// revealForeignSecret: A's token with the right proofs is unknown under B
// (the secret is not consumed), then revealed under A.
func revealForeignSecret(t *testing.T, h *harness, op operation) {
	t.Helper()
	s := h.createSecretA(t)
	params := map[string]string{"secretToken": s.Token}
	resp := h.call(t, op, hostB, params, s.revealBody())
	wantCode(t, op, hostB, resp, http.StatusNotFound, "not-found")
	noSealed(t, h, op, hostB, resp, s)
	resp = h.call(t, op, hostA, params, s.revealBody())
	if resp.status != http.StatusOK || !strings.Contains(string(resp.body), s.text) {
		t.Fatalf("%s under %s: %d %s", op, hostA, resp.status, resp.body)
	}
}

// listMyForeignSecrets: A's secret is listed for its owner only; the
// other sender of A and the same address in B do not see it, and the
// owner's cookie is unknown under B.
func listMyForeignSecrets(t *testing.T, h *harness, op operation) {
	t.Helper()
	s := h.createSecretA(t)
	senders := h.meSenders(t)
	if resp := h.call(t, op, hostA, nil, "", senders.owner.headers()...); resp.status != http.StatusOK || !strings.Contains(string(resp.body), s.ID) {
		t.Fatalf("%s for its owner: %d %s", op, resp.status, resp.body)
	}
	for _, c := range []meClient{senders.colleague, senders.sameAddressB} {
		resp := h.call(t, op, c.host, nil, "", c.headers()...)
		if resp.status != http.StatusOK || strings.Contains(string(resp.body), s.ID) {
			t.Fatalf("%s under %s for another sender: %d %s", op, c.host, resp.status, resp.body)
		}
		noSealed(t, h, op, c.host, resp, s)
	}
	meRefused(t, h, op, hostB, h.call(t, op, hostB, nil, "", senders.owner.headers()...), http.StatusUnauthorized, "unauthenticated")
}

// deleteMyForeignSecret: neither another sender of A nor the same address
// in B deletes A's secret, nor the owner's cookie under B; its owner does.
func deleteMyForeignSecret(t *testing.T, h *harness, op operation) {
	t.Helper()
	s := h.createSecretA(t)
	senders := h.meSenders(t)
	params := map[string]string{"secretId": s.ID}
	meRefusedForOthers(t, h, op, senders, params, "")
	// B's own secret is unknown to A's sender, under A and under B, and
	// stays active.
	b := h.createSecretOfB(t)
	foreign := map[string]string{"secretId": b.ID}
	meRefused(t, h, op, hostA, h.call(t, op, hostA, foreign, "", senders.owner.headers()...), http.StatusNotFound, "not-found")
	meRefused(t, h, op, hostB, h.call(t, op, hostB, foreign, "", senders.owner.headers()...), http.StatusUnauthorized, "unauthenticated")
	link := operation{id: "getSecretLink", verb: http.MethodGet, template: "/secret-links/{secretToken}", base: "/api/v1"}
	if resp := h.call(t, link, hostB, map[string]string{"secretToken": b.Token}, ""); resp.status != http.StatusOK ||
		!strings.Contains(string(resp.body), `"state":"active"`) {
		t.Errorf("%s: B's secret after the attempts: %d %s, want active", op, resp.status, resp.body)
	}
	if resp := h.call(t, op, hostA, params, "", senders.owner.headers()...); resp.status != http.StatusNoContent {
		t.Fatalf("%s by its owner: %d %s", op, resp.status, resp.body)
	}
}

// fileSecretA is a secret of tenant A with an uploaded file.
type fileSecretA struct {
	createdSecretA
	stream string
}

// createFileSecretA creates, through the API under A, a secret of A's
// owner declaring a file, and returns it with the file stream (not
// uploaded yet).
func (h *harness) createFileSecretA(t *testing.T) fileSecretA {
	t.Helper()
	s := fileSecretA{createdSecretA: createdSecretA{sealedSecret: sealSecret(t, "isolation secret with a file")}}
	key, err := tte2.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, _ := tte2.NewWriter(&buf, key, 0)
	_, _ = w.Write([]byte("isolation file content"))
	_ = w.Close()
	s.stream = buf.String()
	sum := sha256.Sum256([]byte("isolation file content"))
	meta, err := tte2.SealMetadata(key, 0, tte2.Metadata{Count: 1, Name: "a.txt", Size: 22, SHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(s.createBody(), `}`, `,"file":{"size":`+strconv.Itoa(buf.Len())+`,"encryptedMetadata":"`+meta+`"}}`, 1)
	resp := h.call(t, opCreateSecret, hostA, nil, body, h.owner(t).headers()...)
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &s.createdSecretA) != nil || !strings.Contains(string(resp.body), `"pending"`) {
		t.Fatalf("create file secret under %s: %d %s", hostA, resp.status, resp.body)
	}
	return s
}

// opUploadSecretFile is the uploadSecretFile operation.
var opUploadSecretFile = operation{id: "uploadSecretFile", verb: http.MethodPut, template: "/secrets/{secretId}/file", base: "/api/v1"}

// uploadForeignSecretFile: A's session is unauthenticated under B, B's
// session is unknown under A, and A's secret stays pending until its owner
// uploads the file under A.
func uploadForeignSecretFile(t *testing.T, h *harness, op operation) {
	t.Helper()
	s := h.createFileSecretA(t)
	params := map[string]string{"secretId": s.ID}
	raw := "Content-Type"
	resp := h.call(t, op, hostB, params, s.stream, h.owner(t).headers(raw, "application/octet-stream")...)
	refusedUnderB(t, h, op, resp, http.StatusUnauthorized, "unauthenticated")
	resp = h.call(t, op, hostA, params, s.stream, h.other(t).headers(raw, "application/octet-stream")...)
	wantCode(t, op, hostA, resp, http.StatusUnauthorized, "unauthenticated")
	noSealed(t, h, op, hostA, resp, s.createdSecretA)
	resp = h.call(t, op, hostA, params, s.stream, h.owner(t).headers(raw, "application/octet-stream")...)
	if resp.status != http.StatusOK || !strings.Contains(string(resp.body), `"state":"active"`) {
		t.Fatalf("%s by its owner under %s: %d %s", op, hostA, resp.status, resp.body)
	}
}

// downloadForeignSecretFile: the token and the grant of A's revealed
// secret are unknown under B (the grant is not consumed), then the file is
// downloaded under A, once.
func downloadForeignSecretFile(t *testing.T, h *harness, op operation) {
	t.Helper()
	s := h.createFileSecretA(t)
	raw := "Content-Type"
	if resp := h.call(t, opUploadSecretFile, hostA, map[string]string{"secretId": s.ID}, s.stream,
		h.owner(t).headers(raw, "application/octet-stream")...); resp.status != http.StatusOK {
		t.Fatalf("upload under %s: %d %s", hostA, resp.status, resp.body)
	}
	reveal := operation{id: "revealSecret", verb: http.MethodPost, template: "/secret-links/{secretToken}/reveal", base: "/api/v1"}
	params := map[string]string{"secretToken": s.Token}
	resp := h.call(t, reveal, hostA, params, s.revealBody())
	var rv struct {
		FileGrant string `json:"fileGrant"`
	}
	if resp.status != http.StatusOK || json.Unmarshal(resp.body, &rv) != nil || rv.FileGrant == "" {
		t.Fatalf("reveal under %s: %d %s", hostA, resp.status, resp.body)
	}
	grant := []string{"TransTeira-Secret-Grant", rv.FileGrant}
	resp = h.call(t, op, hostB, params, "", grant...)
	wantCode(t, op, hostB, resp, http.StatusNotFound, "not-found")
	noSealed(t, h, op, hostB, resp, s.createdSecretA)
	if strings.Contains(string(resp.body), s.stream) {
		t.Errorf("%s under %s leaks the file", op, hostB)
	}
	resp = h.call(t, op, hostA, params, "", grant...)
	if resp.status != http.StatusOK || string(resp.body) != s.stream {
		t.Fatalf("%s under %s: %d (%d bytes)", op, hostA, resp.status, len(resp.body))
	}
	resp = h.call(t, op, hostA, params, "", grant...)
	wantCode(t, op, hostA, resp, http.StatusNotFound, "not-found")
}

// sendForeignSecret: A's session is unauthenticated under B and B's under
// A; B's e-mail secret is unknown to A's owner under A; A's owner reaches
// the send call of its own secret under A only (503 mail-unavailable: A
// has no SMTP settings in the harness, so nothing is activated), and no
// answer echoes the token or the key.
func sendForeignSecret(t *testing.T, h *harness, op operation) {
	t.Helper()
	s := createdSecretA{sealedSecret: sealSecret(t, "isolation e-mail secret")}
	resp := h.call(t, opCreateSecret, hostA, nil, s.createBodyEmail(), h.owner(t).headers()...)
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &s) != nil || s.Token == "" {
		t.Fatalf("create e-mail secret under %s: %d %s", hostA, resp.status, resp.body)
	}
	k, err := tte2.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := tte2.EncodeKey(k)
	sendBody := `{"secretToken":"` + s.Token + `","fragmentKey":"` + key + `"}`
	params := map[string]string{"secretId": s.ID}
	check := func(host string, resp response) {
		t.Helper()
		noSealed(t, h, op, host, resp, s)
		if strings.Contains(string(resp.body), key) {
			t.Errorf("%s under %s echoes the key", op, host)
		}
	}
	resp = h.call(t, op, hostB, params, sendBody, h.owner(t).headers()...)
	refusedUnderB(t, h, op, resp, http.StatusUnauthorized, "unauthenticated")
	check(hostB, resp)
	resp = h.call(t, op, hostA, params, sendBody, h.other(t).headers()...)
	wantCode(t, op, hostA, resp, http.StatusUnauthorized, "unauthenticated")
	check(hostA, resp)

	// B's own e-mail secret is unknown to A's owner, under A.
	var b createdSecretA
	resp = h.call(t, opCreateSecret, hostB, nil, sealSecret(t, "B").createBodyEmail(), h.other(t).headers()...)
	if resp.status != http.StatusCreated || json.Unmarshal(resp.body, &b) != nil {
		t.Fatalf("create e-mail secret under %s: %d %s", hostB, resp.status, resp.body)
	}
	foreign := `{"secretToken":"` + b.Token + `","fragmentKey":"` + key + `"}`
	resp = h.call(t, op, hostA, map[string]string{"secretId": b.ID}, foreign, h.owner(t).headers()...)
	wantCode(t, op, hostA, resp, http.StatusNotFound, "not-found")
	check(hostA, resp)

	resp = h.call(t, op, hostA, params, sendBody, h.owner(t).headers()...)
	wantCode(t, op, hostA, resp, http.StatusServiceUnavailable, "mail-unavailable")
	check(hostA, resp)
}

// createBodyEmail is the creation body of s for an e-mail delivery.
func (s sealedSecret) createBodyEmail() string {
	return strings.Replace(s.createBody(), `"delivery":"link"`, `"delivery":"email","recipient":"carol@customer.example.net"`, 1)
}
