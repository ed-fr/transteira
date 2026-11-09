package store

import (
	"context"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// TestSenderActivityCountsSecrets checks that the one-time secrets a sender
// created in the window count as transfers in the number (never in the
// volume), per creator kind, without the pending ones, and stay in their
// tenant (V2.1, threat T-340).
func TestSenderActivityCountsSecrets(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		f := newSecretFixture(t, e)
		start, end := f.now.Add(-time.Hour), f.now.Add(time.Hour)
		activity := func(tid tenant.ID, kinds ...DepositorKind) int {
			t.Helper()
			bytes, count, err := f.db.Transfers().SenderActivity(ctx, tid, "alice@a.example.com", start, end, kinds)
			if err != nil || bytes != 0 {
				t.Fatalf("SenderActivity = %d, %d, %v", bytes, count, err)
			}
			return count
		}
		if n := activity(f.a); n != 0 {
			t.Fatalf("activity before = %d", n)
		}
		f.create(ctx, t, f.a, f.input(newProofs()))
		f.create(ctx, t, f.a, f.input(newProofs()))
		tokIn := f.input(newProofs())
		tokIn.CreatorKind, tokIn.APITokenID = SecretCreatorAPIToken, f.apiToken(t, f.a)
		f.create(ctx, t, f.a, tokIn)
		// A secret created outside the window and a pending one do not count.
		old := f.input(newProofs())
		old.Now = f.now.Add(-48 * time.Hour)
		f.create(ctx, t, f.a, old)
		inv := f.invitation(t, f.a, "alice@a.example.com", "bob@a.example.com")
		ext := f.input(newProofs())
		ext.CreatorKind, ext.InvitationID = SecretCreatorExternal, inv
		if s := f.create(ctx, t, f.a, ext).Secret; s.State != SecretPending {
			t.Fatalf("external secret state = %s", s.State)
		}

		if n := activity(f.a); n != 3 {
			t.Errorf("all kinds = %d, want 3", n)
		}
		if n := activity(f.a, DepositorInternal); n != 3 {
			t.Errorf("internal (token included) = %d, want 3", n)
		}
		if n := activity(f.a, DepositorExternal); n != 0 {
			t.Errorf("external = %d, want 0 (pending)", n)
		}
		if n := activity(f.b); n != 0 {
			t.Errorf("tenant b = %d, want 0", n)
		}
	})
}

// TestSenderActivitySecretFaults covers the failures of the secret count
// (SQLite with injected faults).
func TestSenderActivitySecretFaults(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, plan := openFault(t)
	f := newSecretFixtureDB(t, db)
	f.create(ctx, t, f.a, f.input(newProofs()))
	start, end := f.now.Add(-time.Hour), f.now.Add(time.Hour)
	for _, op := range []string{faultQuery, faultScanNil} {
		plan.add(op, "GROUP BY creator_kind", 0)
		if _, _, err := db.Transfers().SenderActivity(ctx, f.a, "alice@a.example.com", start, end, nil); err == nil {
			t.Errorf("%s fault: no error", op)
		}
		plan.reset()
	}
}
