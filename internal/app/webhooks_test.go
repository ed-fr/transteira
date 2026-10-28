package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/webhookadmin"
)

// withBusReady hands the started event bus and the webhook service of Run
// to ready.
func withBusReady(ready func(events.Publisher, *webhookadmin.Service)) Option {
	return func(o *runOptions) { o.busReady = ready }
}

// hookRequest is a request received by a hookReceiver.
type hookRequest struct {
	header http.Header
	body   []byte
}

// hookReceiver is a local webhook receiver answering 204.
type hookReceiver struct {
	srv     *httptest.Server
	mu      sync.Mutex
	got     []hookRequest
	arrived chan struct{} // one signal per request received
}

func newHookReceiver(t *testing.T) *hookReceiver {
	t.Helper()
	r := &hookReceiver{arrived: make(chan struct{}, 16)}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.got = append(r.got, hookRequest{header: req.Header.Clone(), body: body})
		r.mu.Unlock()
		select {
		case r.arrived <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

// wait waits until r has received a request, at most startupTimeout.
func (r *hookReceiver) wait(t *testing.T, what string) {
	t.Helper()
	select {
	case <-r.arrived:
	case <-time.After(startupTimeout):
		t.Fatalf("no delivery to %s", what)
	}
}

func (r *hookReceiver) requests() []hookRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]hookRequest(nil), r.got...)
}

// checkHookSignature verifies the X-TransTeira-Signature of req with
// secret, as a receiver would.
func checkHookSignature(t *testing.T, req hookRequest, secret string) {
	t.Helper()
	ts, sig, ok := strings.Cut(req.header.Get("X-TransTeira-Signature"), ",")
	if !ok || !strings.HasPrefix(ts, "t=") || !strings.HasPrefix(sig, "v1=") {
		t.Fatalf("signature %q", req.header.Get("X-TransTeira-Signature"))
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strings.TrimPrefix(ts, "t=") + "."))
	mac.Write(req.body)
	if !hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(strings.TrimPrefix(sig, "v1="))) {
		t.Error("the signature does not verify with the secret of the webhook")
	}
}

// TestRunWebhookDelivery checks the wiring of the webhook dispatcher: on a
// running server, an event of tenant A reaches the webhook of A only,
// signed with its secret, and a system event reaches the instance-wide
// webhook only (T-179).
func TestRunWebhookDelivery(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		cfg := testConfig(t, e)
		prepare(t, cfg)
		// A second tenant, and the ID of the first.
		c := *cfg
		db, err := store.Open(ctx, &c)
		if err != nil {
			t.Fatal(err)
		}
		b, err := db.Tenants().Create(ctx, &tenant.Tenant{
			Name: "Entity B", FQDN: "transfer.entity-b.localhost", DefaultLanguage: "en",
			MaxTransferBytes: 1 << 30, StorageQuotaBytes: 10 << 30,
		})
		if err != nil {
			t.Fatal(err)
		}
		page, err := db.Tenants().List(ctx, store.TenantListOptions{})
		_ = db.Close()
		if err != nil {
			t.Fatal(err)
		}
		var a tenant.ID
		for _, tn := range page.Items {
			if tn.FQDN == tenantHost {
				a = tn.ID
			}
		}

		if e.Driver == config.DriverPostgres {
			cfg.DBMigrateDSN = config.Secret{}
		}
		cfg.ClamAV.Address = fakeClamd(t)
		loopback := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
		cfg.WebhookAllowNetworks, cfg.WebhookAllowHTTPNetworks = loopback, loopback
		type ready struct {
			bus   events.Publisher
			hooks *webhookadmin.Service
		}
		readyCh := make(chan ready, 1)
		s := start(t, cfg, withBusReady(func(p events.Publisher, h *webhookadmin.Service) { readyCh <- ready{p, h} }))
		var r ready
		select {
		case r = <-readyCh:
		case <-time.After(30 * time.Second):
			t.Fatalf("the server did not start: %s", s.logs.String())
		}

		super := adminauth.Principal{
			SessionID: id.New(id.AdminSession), State: store.SessionAuthenticated,
			Admin: adminauth.Account{ID: id.New(id.Admin), Username: "root", Role: store.RoleSuperAdmin},
		}
		ip := netip.MustParseAddr("192.0.2.30")
		recvA, recvB, recvSys := newHookReceiver(t), newHookReceiver(t), newHookReceiver(t)
		input := func(rcv *hookReceiver, ev events.Type) webhookadmin.CreateInput {
			return webhookadmin.CreateInput{
				Name: "SIEM collector", Kind: store.WebhookGeneric, URL: rcv.srv.URL + "/hook", Events: []events.Type{ev},
			}
		}
		hookA, err := r.hooks.CreateTenant(ctx, super, a, input(recvA, events.VirusDetected), ip)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.hooks.CreateTenant(ctx, super, b.ID, input(recvB, events.VirusDetected), ip); err != nil {
			t.Fatal(err)
		}
		hookSys, err := r.hooks.CreateSystem(ctx, super, input(recvSys, events.DiskAlertRaised), ip)
		if err != nil {
			t.Fatal(err)
		}

		r.bus.Publish(events.Event{
			ID: id.New(id.Event), Type: events.VirusDetected, Severity: events.SeverityCritical,
			OccurredAt: time.Now(), TenantID: string(a), Counts: map[string]float64{"files": 1},
			AdminPath: events.AdminPathTenantAudit(string(a)),
		})
		r.bus.Publish(events.Event{
			ID: id.New(id.Event), Type: events.DiskAlertRaised, Severity: events.SeverityWarning,
			OccurredAt: time.Now(), Counts: map[string]float64{"usedRatio": 0.9}, AdminPath: events.AdminPathSystem,
		})
		recvA.wait(t, "the webhook of tenant A")
		recvSys.wait(t, "the system webhook")
		// The dispatcher handles the events in their order of publication and
		// each webhook delivers its queue in order: had the event of A been
		// routed to the webhook of B, it would reach B before this event of B.
		r.bus.Publish(events.Event{
			ID: id.New(id.Event), Type: events.VirusDetected, Severity: events.SeverityCritical,
			OccurredAt: time.Now(), TenantID: string(b.ID), Counts: map[string]float64{"files": 1},
			AdminPath: events.AdminPathTenantAudit(string(b.ID)),
		})
		recvB.wait(t, "the webhook of tenant B")
		if first := recvB.requests()[0]; !strings.Contains(string(first.body), string(b.ID)) {
			t.Fatalf("first delivery to B is not the event of B: %s", first.body)
		}
		gotA, gotB, gotSys := recvA.requests(), recvB.requests(), recvSys.requests()
		if len(gotA) != 1 || len(gotB) != 1 || len(gotSys) != 1 {
			t.Fatalf("deliveries: A %d, B %d, system %d", len(gotA), len(gotB), len(gotSys))
		}
		if gotA[0].header.Get("X-TransTeira-Event") != string(events.VirusDetected) ||
			gotSys[0].header.Get("X-TransTeira-Event") != string(events.DiskAlertRaised) {
			t.Errorf("event headers: %q, %q", gotA[0].header.Get("X-TransTeira-Event"), gotSys[0].header.Get("X-TransTeira-Event"))
		}
		checkHookSignature(t, gotA[0], hookA.Secret)
		checkHookSignature(t, gotSys[0], hookSys.Secret)
		if strings.Contains(string(gotSys[0].body), string(a)) {
			t.Errorf("the system payload names a tenant: %s", gotSys[0].body)
		}
		if err := s.stop(t); err != nil {
			t.Fatalf("Run = %v", err)
		}
	})
}
