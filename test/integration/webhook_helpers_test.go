package integration_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// Helpers of the webhook administration tests (CLAUDE.md section 12.4;
// api/openapi.yaml webhook operations; threat model T-181 to T-186).

const (
	// pathSystemWebhooks is the collection of the instance-wide webhooks.
	pathSystemWebhooks = "/api/v1/admin/system/webhooks"
	// webhookURLToken is the secret part of the receiver URL (Teams and
	// Slack URLs embed one): it must never appear in an answer, the audit
	// log or a log.
	webhookURLToken = "EXAMPLEwebhookURLtoken42"
	// Audit actions of the webhooks.
	actWebhookCreated = "webhook.created"
	actWebhookUpdated = "webhook.updated"
	actWebhookTested  = "webhook.tested"
	actWebhookDeleted = "webhook.deleted"
	// webhookTestLimit is webhookadmin.TestLimit.
	webhookTestLimit = 10
	// maxWebhooks is store.MaxWebhooks.
	maxWebhooks = 20
)

// webhookSecretRE is the format of a signing secret: 64 lowercase
// hexadecimal characters, used as is as the HMAC key.
var webhookSecretRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// webhookMembers are the members of the Webhook schema (all required);
// WebhookWithSecret adds secret.
var webhookMembers = []string{
	"id", "name", "kind", "urlHint", "events", "enabled", "hasSecret", "createdBy", "createdAt", "updatedAt",
	"lastDelivery", "circuitOpenUntil",
}

// webhookDeliveryMembers are the members of the WebhookDelivery schema.
var webhookDeliveryMembers = []string{"at", "success", "httpStatus", "durationMs", "errorCategory"}

// webhookJSON is the Webhook schema, with the secret of WebhookWithSecret.
type webhookJSON struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Kind             string     `json:"kind"`
	URLHint          string     `json:"urlHint"`
	Events           []string   `json:"events"`
	Enabled          bool       `json:"enabled"`
	HasSecret        bool       `json:"hasSecret"`
	CreatedBy        string     `json:"createdBy"`
	CreatedAt        time.Time  `json:"createdAt"`
	UpdatedAt        time.Time  `json:"updatedAt"`
	LastDelivery     *struct{}  `json:"lastDelivery"`
	CircuitOpenUntil *time.Time `json:"circuitOpenUntil"`
	Secret           string     `json:"secret"`
}

// webhookTestJSON is the WebhookTestResult schema.
type webhookTestJSON struct {
	Success       bool   `json:"success"`
	HTTPStatus    int    `json:"httpStatus"`
	DurationMs    int    `json:"durationMs"`
	ErrorCategory string `json:"errorCategory"`
}

// receivedRequest is a request received by the webhook receiver.
type receivedRequest struct {
	header http.Header
	body   []byte
}

// webhookReceiver is a local HTTP receiver answering 200, reached through
// TT_WEBHOOK_ALLOW_NETWORKS and TT_WEBHOOK_ALLOW_HTTP_NETWORKS.
type webhookReceiver struct {
	srv *httptest.Server
	mu  sync.Mutex
	got []receivedRequest
}

// newWebhookReceiver starts a receiver, closed when the test ends.
func newWebhookReceiver(t *testing.T) *webhookReceiver {
	t.Helper()
	r := &webhookReceiver{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.got = append(r.got, receivedRequest{header: req.Header.Clone(), body: body})
		r.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

// url returns the URL of the receiver, with its secret token.
func (r *webhookReceiver) url() string {
	return r.srv.URL + "/hooks/transteira?token=" + webhookURLToken
}

// hint returns the expected urlHint of the receiver.
func (r *webhookReceiver) hint() string { return r.srv.URL }

// last returns the last request received.
func (r *webhookReceiver) last(t *testing.T) receivedRequest {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.got) == 0 {
		t.Fatal("the receiver got no request")
	}
	return r.got[len(r.got)-1]
}

// startWebhookAdmin starts an admin server whose webhooks may reach the
// loopback receiver, bootstraps the super admin and a delegated admin of
// tenant A, and returns them.
func startWebhookAdmin(t *testing.T, e storetest.Engine) (a *adminEnv, sa, da *adminClient) {
	t.Helper()
	a = startAdmin(t, e, serverOptions{env: map[string]string{
		config.EnvWebhookAllowNetworks:     "127.0.0.0/8",
		config.EnvWebhookAllowHTTPNetworks: "127.0.0.0/8",
	}}, false)
	a.secret(webhookURLToken)
	sa = a.bootstrap(t, adminIP(30))
	da = sa.createDelegatedOf(t, "delegate-webhooks", string(a.tenantA.ID), domainA, adminIP(31))
	return a, sa, da
}

// webhooksPath returns the admin path of the webhooks of tenant tid.
func webhooksPath(tid string) string { return tenantPath(tid, "/webhooks") }

// checkWebhookMembers checks the members of a Webhook (with secret when
// withSecret) and of its last delivery.
func checkWebhookMembers(t *testing.T, schema string, raw []byte, withSecret bool) {
	t.Helper()
	var members map[string]json.RawMessage
	mustJSON(t, raw, &members)
	allowed := slices.Clone(webhookMembers)
	if withSecret {
		allowed = append(allowed, "secret")
	}
	checkMembers(t, schema, members, allowed, webhookMembers)
	if d := members["lastDelivery"]; len(d) > 0 && string(d) != "null" {
		var dm map[string]json.RawMessage
		mustJSON(t, d, &dm)
		checkMembers(t, "WebhookDelivery", dm, webhookDeliveryMembers, []string{"at", "success", "durationMs"})
	}
}

// createWebhook sends createTenantWebhook (or createSystemWebhook when tid
// is "") and returns the answer.
func (c *adminClient) createWebhook(t *testing.T, tid string, body map[string]any) response {
	t.Helper()
	path := pathSystemWebhooks
	if tid != "" {
		path = webhooksPath(tid)
	}
	return c.call(t, http.MethodPost, path, body)
}

// mustCreateWebhook creates a webhook, checks the WebhookWithSecret answer
// and records its secret as one that must never be logged.
func (c *adminClient) mustCreateWebhook(t *testing.T, tid string, body map[string]any) webhookJSON {
	t.Helper()
	resp := mustStatus(t, "createWebhook", c.createWebhook(t, tid, body), http.StatusCreated)
	if cc := resp.header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("createWebhook Cache-Control = %q, want no-store", cc)
	}
	checkWebhookMembers(t, "WebhookWithSecret", resp.body, true)
	var w webhookJSON
	mustJSON(t, resp.body, &w)
	if !id.Valid(id.Webhook, w.ID) {
		t.Errorf("webhook id %q, want a whk_ identifier", w.ID)
	}
	if w.Secret != "" {
		c.a.secret(w.Secret)
	}
	if strings.Contains(string(resp.body), webhookURLToken) {
		t.Errorf("createWebhook answer holds the url token: %s", resp.body)
	}
	return w
}

// listWebhooks lists the webhooks of tenant tid ("" for the instance) and
// checks the members of each item.
func (c *adminClient) listWebhooks(t *testing.T, tid string) []webhookJSON {
	t.Helper()
	path := pathSystemWebhooks
	if tid != "" {
		path = webhooksPath(tid)
	}
	resp := mustStatus(t, "listWebhooks", c.call(t, http.MethodGet, path, nil), http.StatusOK)
	var items []json.RawMessage
	mustJSON(t, resp.body, &items)
	for _, it := range items {
		checkWebhookMembers(t, "Webhook", it, false)
	}
	var list []webhookJSON
	mustJSON(t, resp.body, &list)
	return list
}

// verifySignature checks the X-TransTeira-Signature of r against secret,
// as a receiver would (api/openapi.yaml WebhookEvent).
func verifySignature(t *testing.T, r receivedRequest, secret string) {
	t.Helper()
	sig := r.header.Get("X-TransTeira-Signature")
	parts := strings.Split(sig, ",")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "t=") || !strings.HasPrefix(parts[1], "v1=") {
		t.Fatalf("signature %q, want t=<unix seconds>,v1=<hex>", sig)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strings.TrimPrefix(parts[0], "t=") + "."))
	mac.Write(r.body)
	if want := hex.EncodeToString(mac.Sum(nil)); !hmac.Equal([]byte(want), []byte(strings.TrimPrefix(parts[1], "v1="))) {
		t.Errorf("signature %q does not verify with the secret", sig)
	}
}
