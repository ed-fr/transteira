package datasubject

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

func TestNew(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		if _, err := New(nil, Options{Eraser: ev.eraser}); !errors.Is(err, errMissingDependency) {
			t.Errorf("New(nil db) = %v", err)
		}
		if _, err := New(ev.db, Options{}); !errors.Is(err, errMissingDependency) {
			t.Errorf("New(no eraser) = %v", err)
		}
		s, err := New(ev.db, Options{Eraser: ev.eraser})
		if err != nil || s.logger == nil || s.now == nil || s.sleep == nil {
			t.Fatalf("New defaults = %+v, %v", s, err)
		}
		release, err := s.holder.Hold(context.Background(), ev.a.ID, "trf_x", lifecycle.HoldForEdit)
		if err != nil {
			t.Fatal(err)
		}
		release()
	})
}

func TestSleepContext(t *testing.T) {
	if err := sleepContext(context.Background(), time.Millisecond); err != nil {
		t.Errorf("sleepContext = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepContext(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("sleepContext canceled = %v", err)
	}
}

func TestPseudonym(t *testing.T) {
	salt := make([]byte, saltSize)
	p1, p2 := pseudonymOf(salt, carol), pseudonymOf(salt, carol)
	if p1 != p2 || !store.IsPseudonym(p1) {
		t.Errorf("pseudonymOf = %q, %q", p1, p2)
	}
	if pseudonymOf(salt, dave) == p1 {
		t.Error("two addresses share a pseudonym")
	}
	salt[0] = 1
	if pseudonymOf(salt, carol) == p1 {
		t.Error("two salts give the same pseudonym")
	}
	n1, n2 := newPseudonym(carol), newPseudonym(carol)
	if n1 == n2 || !store.IsPseudonym(n1) || strings.Contains(n1, "carol") {
		t.Errorf("newPseudonym = %q, %q", n1, n2)
	}
}

func TestRights(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		disabled := principal(store.RoleDelegatedAdmin, "dis", ev.a.ID)
		disabled.Admin.Disabled = true
		ops := map[string]func(p adminauth.Principal, tid tenant.ID, email string) error{
			"search": func(p adminauth.Principal, tid tenant.ID, email string) error {
				_, err := ev.svc.Search(ctx, p, clientIP, tid, email)
				return err
			},
			"erase": func(p adminauth.Principal, tid tenant.ID, email string) error {
				_, err := ev.svc.Erase(ctx, p, clientIP, tid, email)
				return err
			},
		}
		for name, op := range ops {
			wantErr(t, name+" unauthenticated", op(adminauth.Principal{}, ev.a.ID, carol), ErrUnauthenticated)
			wantErr(t, name+" other tenant", op(ev.adminB, ev.a.ID, carol), ErrNotFound)
			wantErr(t, name+" disabled", op(disabled, ev.a.ID, carol), ErrNotFound)
			wantErr(t, name+" unknown tenant", op(ev.super, tenant.ID("tnt_01JZZZZZZZZZZZZZZZZZZZZZZZ"), carol), ErrNotFound)
			// Only a bare dot-atom address the store can keep is accepted:
			// the search echoes it as the OpenAPI Email.
			for _, bad := range []string{
				"not an address", "Carol <carol@customer.example.net>", "<carol@customer.example.net>",
				"\"c d\"@customer.example.net", "carol@customer.example.net, dan@customer.example.net",
				"carol@example.123", "carol@xn--a.example.com",
			} {
				err := op(ev.adminA, ev.a.ID, bad)
				var ie *InvalidError
				if !errors.As(err, &ie) || !errors.Is(err, ErrInvalid) || ie.Field != FieldEmail ||
					!strings.Contains(ie.Error(), FieldEmail) || strings.Contains(ie.Error(), bad) {
					t.Errorf("%s invalid %q = %v", name, bad, err)
				}
			}
			if err := op(ev.adminA, ev.a.ID, carol); err != nil {
				t.Errorf("%s by the tenant admin = %v", name, err)
			}
			if err := op(ev.adminB, ev.b.ID, carol); err != nil {
				t.Errorf("%s by the other tenant admin = %v", name, err)
			}
		}

		// A tenant being deleted is answered like a missing one.
		if err := ev.db.Tenants().SetStatus(ctx, ev.b.ID, tenant.StatusDeleting); err != nil {
			t.Fatal(err)
		}
		for name, op := range ops {
			wantErr(t, name+" deleting tenant", op(ev.super, ev.b.ID, carol), ErrNotFound)
		}

		// A failure to read the tenant is internal.
		ev.faults("getTenant")
		for name, op := range ops {
			err := op(ev.super, ev.a.ID, carol)
			if !errors.Is(err, errBoom) || errors.Is(err, ErrNotFound) {
				t.Errorf("%s getTenant failure = %v", name, err)
			}
		}
	})
}

func TestSearchFailures(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.seed(ev.a)
		for _, m := range []string{"senderTransfers", "recipientTransfers", "countInvitations", "verified", "countAudit"} {
			ev.faults(m)
			_, err := ev.svc.Search(context.Background(), ev.super, clientIP, ev.a.ID, carol)
			wantErr(t, m, err, errBoom)
		}
		ev.faults("audit")
		if got := ev.search(ev.a, carol); got.TransfersAsSender != 2 {
			t.Errorf("Search = %+v", got)
		}
		if !strings.Contains(ev.logs.String(), "audit write failed") {
			t.Errorf("audit failure not logged:\n%s", ev.logs.String())
		}
	})
}

func TestSearchOtherTenantIsolated(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.seed(ev.b)
		if got := ev.search(ev.a, carol); got != (Summary{Email: carol}) {
			t.Errorf("Search A = %+v", got)
		}
		if rep := ev.erase(ev.a, carol); rep != (EraseReport{}) {
			t.Errorf("Erase A = %+v", rep)
		}
		if got := ev.search(ev.b, carol); got.TransfersAsSender != 2 || !got.VerifiedAddress || got.AuditEvents != 3 {
			t.Errorf("Search B = %+v", got)
		}
	})
}
