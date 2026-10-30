package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// waitingTransfer stores, in the database of cfg, a transfer of the test
// tenant waiting for the antivirus (scanning, one pending file), and
// returns the tenant and the transfer.
func waitingTransfer(t *testing.T, cfg *config.Config) (tenant.ID, string) {
	t.Helper()
	ctx := context.Background()
	c := *cfg
	db, err := store.Open(ctx, &c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	raw, err := os.ReadFile(cfg.MasterKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	mk, err := crypto.ParseMasterKey(bytes.TrimSpace(raw))
	if err != nil {
		t.Fatal(err)
	}
	kr, err := masterkey.New(mk, nil)
	if err != nil {
		t.Fatal(err)
	}
	tn, err := db.Tenants().TenantByFQDN(ctx, tenantHost)
	if err != nil {
		t.Fatal(err)
	}
	vault := masterkey.NewVault(db, kr, nil)
	scoped, err := db.Scoped(tn.ID)
	if err != nil {
		t.Fatal(err)
	}
	trfID := id.New(id.Transfer)
	err = scoped.Tx(ctx, func(tx *store.ScopedTx) error {
		wk, _, err := vault.NewDEKTx(ctx, tx)
		if err != nil {
			return err
		}
		upl, err := id.NewUploadToken()
		if err != nil {
			return err
		}
		f := store.TransferFile{
			ID: id.New(id.File), Name: "report.pdf", Size: 10, DEKKeyID: wk, StorageName: strings.Repeat("ab", 16),
			UploadID: upl, SHA256: strings.Repeat("11", 32), CiphertextSize: 58, UploadedAt: time.Now(),
		}
		tr := store.Transfer{
			ID: trfID, SenderEmail: "alice@entity-a.localhost", SenderKind: store.DepositorInternal, ExpiryDays: 7,
			LinkMode: store.LinkModePerRecipient,
		}
		if err := db.Transfers().CreateTx(ctx, tx, tr, []string{"bob@partner.example.org"}, []store.TransferFile{f}); err != nil {
			return err
		}
		return db.Transfers().FinalizeTx(ctx, tx, trfID, time.Now())
	})
	if err != nil {
		t.Fatal(err)
	}
	return tn.ID, trfID
}

// TestRunAntivirusEngineNone starts the instance with TT_ANTIVIRUS_ENGINE
// none and clamd unreachable: the start-up releases the file waiting for a
// scan (audited once), the worker makes its transfer available without any
// engine, /healthz answers ok and a warning is logged.
func TestRunAntivirusEngineNone(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		cfg := testConfig(t, e)
		prepare(t, cfg)
		tid, trfID := waitingTransfer(t, cfg)
		if e.Driver == config.DriverPostgres {
			cfg.DBMigrateDSN = config.Secret{}
		}
		cfg.AntivirusEngine = config.EngineNone
		s := start(t, cfg)

		if code, body := s.get(t, "/healthz", "anything"); code != http.StatusOK || !strings.Contains(body, `"antivirus":"ok"`) {
			t.Fatalf("healthz = %d %s", code, body)
		}

		ctx := context.Background()
		c := *cfg
		db, err := store.Open(ctx, &c)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		deadline := time.Now().Add(20 * time.Second)
		for {
			d, err := db.Transfers().Get(ctx, tid, trfID)
			if err != nil {
				t.Fatal(err)
			}
			if d.Status == store.TransferAvailable {
				if d.Files[0].ScanStatus != store.ScanNotScannedDisabled {
					t.Fatalf("file %+v", d.Files[0])
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("transfer %s (file %s)\nlogs: %s", d.Status, d.Files[0].ScanStatus, s.logs.String())
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err := s.stop(t); err != nil {
			t.Fatalf("Run = %v", err)
		}
		page, err := db.AuditEvents().List(ctx, store.AuditFilter{Action: string(audit.ActionAntivirusScansReleased)})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != 1 || page.Items[0].TenantID != "" || page.Items[0].ActorKind != store.ActorSystem {
			t.Fatalf("scans_released events %+v", page.Items)
		}
		var details struct{ Files int }
		if err := json.Unmarshal(page.Items[0].Details, &details); err != nil || details.Files != 1 {
			t.Errorf("details %s, %v", page.Items[0].Details, err)
		}
		logs := s.logs.String()
		for _, want := range []string{"antivirus disabled for the whole instance", "released without analysis"} {
			if !strings.Contains(logs, want) {
				t.Errorf("logs lack %q: %s", want, logs)
			}
		}

		// A second start has nothing left to release: no new release
		// event, but the disabled engine is audited at every start.
		s = start(t, cfg)
		if err := s.stop(t); err != nil {
			t.Fatalf("Run = %v", err)
		}
		if page, err := db.AuditEvents().List(ctx, store.AuditFilter{Action: string(audit.ActionAntivirusScansReleased)}); err != nil ||
			len(page.Items) != 1 {
			t.Errorf("events after a second start: %+v, %v", page.Items, err)
		}
		if page, err := db.AuditEvents().List(ctx, store.AuditFilter{Action: string(audit.ActionAntivirusInstanceDisabled)}); err != nil ||
			len(page.Items) != 2 || page.Items[0].TenantID != "" || page.Items[0].ActorKind != store.ActorSystem {
			t.Errorf("instance_disabled events after two starts: %+v, %v", page.Items, err)
		}
	})
}

func TestAntivirusHealth(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{AntivirusEngine: config.EngineNone}
	if err := antivirusHealth(nil).Check(context.Background()); err != nil {
		t.Errorf("engine none: %v", err)
	}
	if got := antivirusEngine(cfg); got != "none" {
		t.Errorf("engine = %q", got)
	}
	if got := antivirusEngine(&config.Config{}); got != "clamd" {
		t.Errorf("default engine = %q", got)
	}
}

// fakeReleaser answers ReleaseAllUnscanned with n and err.
type fakeReleaser struct {
	n   int
	err error
}

func (f fakeReleaser) ReleaseAllUnscanned(context.Context) (int, error) { return f.n, f.err }

// fakeRecorder records the events, failing with err.
type fakeRecorder struct {
	err    error
	events []audit.Event
}

func (f *fakeRecorder) Record(_ context.Context, ev audit.Event) error {
	f.events = append(f.events, ev)
	return f.err
}

func TestReleaseUnscannedErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	boom := errors.New("boom")

	rec := &fakeRecorder{}
	if err := releaseUnscanned(ctx, fakeReleaser{err: boom}, rec, logger); !errors.Is(err, boom) || len(rec.events) != 0 {
		t.Errorf("release failure: %v, %d events", err, len(rec.events))
	}
	if err := releaseUnscanned(ctx, fakeReleaser{}, rec, logger); err != nil || len(rec.events) != 0 {
		t.Errorf("nothing released: %v, %d events", err, len(rec.events))
	}
	// An audit failure is logged, never fatal to the start.
	rec.err = boom
	if err := releaseUnscanned(ctx, fakeReleaser{n: 3}, rec, logger); err != nil || len(rec.events) != 1 {
		t.Errorf("audit failure: %v, %d events", err, len(rec.events))
	}
	if ev := rec.events[0]; ev.Action != audit.ActionAntivirusScansReleased || ev.Actor != audit.ActorAntivirus ||
		ev.Details["files"] != 3 || ev.TenantID != "" {
		t.Errorf("event %+v", ev)
	}
	if !strings.Contains(logs.String(), "audit write failed") {
		t.Errorf("logs %s", logs.String())
	}
}

func TestAuditInstanceDisabled(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))

	rec := &fakeRecorder{}
	auditInstanceDisabled(ctx, rec, logger)
	if len(rec.events) != 1 {
		t.Fatalf("%d events", len(rec.events))
	}
	if ev := rec.events[0]; ev.Action != audit.ActionAntivirusInstanceDisabled || ev.Actor != audit.ActorAntivirus ||
		ev.ActorKind != store.ActorSystem || ev.TenantID != "" {
		t.Errorf("event %+v", ev)
	}
	// An audit failure is logged, never fatal to the start.
	rec.err = errors.New("boom")
	auditInstanceDisabled(ctx, rec, logger)
	if !strings.Contains(logs.String(), "audit write failed") {
		t.Errorf("logs %s", logs.String())
	}
}
