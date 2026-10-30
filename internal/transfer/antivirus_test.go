package transfer

import (
	"context"
	"testing"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

func TestFinalizeAntivirus(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		for _, tc := range []struct {
			name           string
			tenantSwitch   bool
			engineDisabled bool
			want           store.ScanStatus
		}{
			{"effective", true, false, store.ScanPending},
			{"tenant switch off", false, false, store.ScanNotScannedDisabled},
			{"instance engine none", true, true, store.ScanNotScannedDisabled},
		} {
			t.Run(tc.name, func(t *testing.T) {
				ctx := context.Background()
				spy := &auditSpy{writer: audit.New(ev.db)}
				ev.withHooks(spy)
				ev.svc.avDisabled = tc.engineDisabled
				tn, err := ev.db.Tenants().SetAntivirusEnabled(ctx, ev.a.ID, tc.tenantSwitch)
				if err != nil {
					t.Fatal(err)
				}
				if got, want := ev.svc.AntivirusEffective(tn), tc.want == store.ScanPending; got != want {
					t.Errorf("AntivirusEffective = %v, want %v", got, want)
				}
				d := ev.mustCreate(t, internalSender(), request())
				ev.complete(t, d.ID, "")
				got, err := ev.svc.Finalize(ctx, tn, internalSender(), d.ID)
				if err != nil {
					t.Fatalf("Finalize: %v", err)
				}
				if got.Status != store.TransferScanning || len(got.Files) != 2 {
					t.Fatalf("finalized = %+v", got)
				}
				for _, f := range got.Files {
					if f.ScanStatus != tc.want {
						t.Errorf("file %s status %q, want %q", f.ID, f.ScanStatus, tc.want)
					}
				}
				events, tids, errs := spy.snapshot()
				if len(errs) > 0 {
					t.Fatalf("audit errors: %v", errs)
				}
				var unscanned []audit.Event
				for i, ev := range events {
					if ev.Action == audit.ActionFileNotScanned {
						unscanned = append(unscanned, ev)
						if tids[i] != tn.ID {
							t.Errorf("event recorded in tenant %s", tids[i])
						}
					}
				}
				if tc.want == store.ScanPending {
					if len(unscanned) != 0 {
						t.Errorf("file.not_scanned recorded with an effective antivirus: %+v", unscanned)
					}
					return
				}
				if len(unscanned) != 2 {
					t.Fatalf("file.not_scanned events = %+v", unscanned)
				}
				for i, ev := range unscanned {
					if ev.ActorKind != store.ActorSystem || ev.Actor != "antivirus" || ev.ObjectKind != audit.ObjectFile ||
						ev.ObjectID != got.Files[i].ID || ev.Details["reason"] != "disabled" || ev.Details["transferId"] != d.ID {
						t.Errorf("event %d = %+v", i, ev)
					}
				}
			})
		}
	})
}

// TestFinalizeAntivirusIsolation checks that a tenant whose antivirus is
// off never changes the files of another tenant.
func TestFinalizeAntivirusIsolation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		d := ev.mustCreate(t, internalSender(), request())
		ev.complete(t, d.ID, "")
		off, err := ev.db.Tenants().SetAntivirusEnabled(ctx, ev.b.ID, false)
		if err != nil {
			t.Fatal(err)
		}
		// B cannot finalize a transfer of A, whatever its antivirus switch.
		if _, err := ev.svc.Finalize(ctx, off, internalSender(), d.ID); err == nil {
			t.Fatal("tenant B finalized a transfer of A")
		}
		got, err := ev.svc.Finalize(ctx, ev.a, internalSender(), d.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range got.Files {
			if f.ScanStatus != store.ScanPending {
				t.Errorf("file of A %q", f.ScanStatus)
			}
		}
	})
}
