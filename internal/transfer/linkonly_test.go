package transfer

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// allowLinkOnly sets the link-only flag of tn in the database (the
// in-memory tn keeps its value: the service reads the current one).
func (ev *env) allowLinkOnly(t *testing.T, tn *tenant.Tenant, on bool) {
	t.Helper()
	if _, err := ev.db.Tenants().SetLinkOnlyAllowed(context.Background(), tn.ID, on); err != nil {
		t.Fatal(err)
	}
}

// linkOnlyRequest is request() as a link-only transfer without recipient.
func linkOnlyRequest() CreateRequest {
	req := request()
	req.Recipients, req.LinkOnly = nil, true
	return req
}

// wantFields checks that err is a *ValidationError with exactly want.
func wantFields(t *testing.T, err error, want []FieldError) {
	t.Helper()
	var verr *ValidationError
	if !errors.As(err, &verr) || !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want a validation error", err)
	}
	if !reflect.DeepEqual(verr.Fields, want) {
		t.Errorf("fields = %+v, want %+v", verr.Fields, want)
	}
}

// TestCreateLinkOnly creates link-only transfers: without recipient (or
// with recipients, recorded), a single shared link, audited with
// linkOnly; the tenant and level switches and the depositor kind are
// enforced.
func TestCreateLinkOnly(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		spy := &auditSpy{writer: audit.New(ev.db)}
		ev.withHooks(spy)

		// The tenant flag is off by default.
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), linkOnlyRequest(), ""); !errors.Is(err, ErrLinkOnlyForbidden) {
			t.Fatalf("tenant off: %v", err)
		}
		ev.allowLinkOnly(t, ev.a, true)
		d := ev.mustCreate(t, internalSender(), linkOnlyRequest())
		if !d.LinkOnly || len(d.Recipients) != 0 || d.DownloadURL != "" || d.RecipientTracking != nil {
			t.Errorf("link-only = %+v", d)
		}
		got, err := ev.db.Transfers().Get(ctx, ev.a.ID, d.ID)
		if err != nil || !got.LinkOnly || got.LinkMode != store.LinkModeShared || got.DropLinkID != "" {
			t.Fatalf("stored = %+v, %v", got.Transfer, err)
		}
		events, _, errs := spy.snapshot()
		if len(errs) != 0 || len(events) != 1 || events[0].Details["linkOnly"] != true || events[0].Details["origin"] != originInternal {
			t.Errorf("audit = %+v %v", events, errs)
		}
		// Recipients may still be named; they are validated.
		req := linkOnlyRequest()
		req.Recipients = []string{dave}
		if d := ev.mustCreate(t, internalSender(), req); !reflect.DeepEqual(d.Recipients, []string{dave}) {
			t.Errorf("recipients = %v", d.Recipients)
		}
		req.Recipients = []string{"not an address"}
		_, err = ev.svc.Create(ctx, ev.a, internalSender(), req, "")
		wantFields(t, err, []FieldError{{Pointer: "/recipients/0", Code: CodeInvalidEmail}})
		// With the recipient verification: a conflict.
		req = linkOnlyRequest()
		req.RecipientVerification = true
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), req, ""); !errors.Is(err, ErrLinkOnlyConflict) {
			t.Errorf("verification: %v", err)
		}
		// An invited external may not.
		if _, err := ev.svc.Create(ctx, ev.a, ev.external(), linkOnlyRequest(), ""); !errors.Is(err, ErrLinkOnlyForbidden) {
			t.Errorf("external: %v", err)
		}
		// An API token may.
		tok := ev.newToken(t, ev.a)
		req = linkOnlyRequest()
		req.SenderEmail = carol
		if _, err := ev.svc.Create(ctx, ev.a, tokenSender(tok), req, ""); err != nil {
			t.Errorf("api token: %v", err)
		}
		// A level that forbids it.
		levels := strictLevels()
		levels[0].LinkOnlyAllowed, levels[1].LinkOnlyAllowed = false, true
		ev.setLevels(t, ev.a, levels)
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), linkOnlyRequest(), ""); !errors.Is(err, ErrLinkOnlyForbidden) {
			t.Errorf("level off: %v", err)
		}
		// Without link-only, the level switch is irrelevant.
		ev.mustCreate(t, internalSender(), request())
		// Tenant B is not concerned by the flag of A.
		if _, err := ev.svc.Create(ctx, ev.b, internalSender(), linkOnlyRequest(), ""); !errors.Is(err, ErrLinkOnlyForbidden) {
			t.Errorf("tenant B: %v", err)
		}
	})
}

// TestCreateLinkOnlyFaults covers the tenant read of the link-only rule.
func TestCreateLinkOnlyFaults(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ev.allowLinkOnly(t, ev.a, true)
	f := ev.faults()
	f.fail["tenant"] = errFault
	if _, err := ev.svc.Create(context.Background(), ev.a, internalSender(), linkOnlyRequest(), ""); !errors.Is(err, errFault) || isClientError(err) {
		t.Errorf("tenant read: %v", err)
	}
	f.fail["tenant"] = store.ErrNotFound
	if _, err := ev.svc.Create(context.Background(), ev.a, internalSender(), linkOnlyRequest(), ""); !errors.Is(err, ErrForbidden) {
		t.Errorf("tenant gone: %v", err)
	}
}

// TestFinalizeLinkOnly returns the link of a link-only transfer once, at
// its finalization, storing its hash only; no other view shows it.
func TestFinalizeLinkOnly(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		ev.allowLinkOnly(t, ev.a, true)
		d := ev.mustCreate(t, internalSender(), linkOnlyRequest())
		ev.complete(t, d.ID, "")
		out, err := ev.svc.Finalize(ctx, ev.a, internalSender(), d.ID)
		if err != nil {
			t.Fatalf("Finalize: %v", err)
		}
		prefix := "https://" + hostA + id.DownloadPath
		token, ok := strings.CutPrefix(out.DownloadURL, prefix)
		if !ok || !id.DownloadTokenValid(token) || !out.LinkOnly || out.Status != store.TransferScanning {
			t.Fatalf("finalized = %+v", out)
		}
		got, err := ev.db.Transfers().Get(ctx, ev.a.ID, d.ID)
		if err != nil || !bytes.Equal(got.DownloadTokenHash, id.HashToken(token)) || got.DownloadTokenKeyID != "" {
			t.Fatalf("stored token: %x %q %v", got.DownloadTokenHash, got.DownloadTokenKeyID, err)
		}
		if _, err := ev.svc.Finalize(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, ErrConflict) {
			t.Errorf("second finalization: %v", err)
		}
		// Available: the hash is kept, and the sender's view has no link.
		s, err := ev.db.Scoped(ev.a.ID)
		if err != nil {
			t.Fatal(err)
		}
		err = s.Tx(ctx, func(tx *store.ScopedTx) error {
			return ev.db.Transfers().MarkLinkOnlyAvailableTx(ctx, tx, d.ID, ev.clock.Now())
		})
		if err != nil {
			t.Fatal(err)
		}
		view, err := ev.svc.Get(ctx, ev.a, internalSender(), d.ID)
		if err != nil || view.Status != store.TransferAvailable || view.DownloadURL != "" || !view.LinkOnly {
			t.Errorf("Get = %+v, %v", view, err)
		}
	})
}

// TestFinalizeLinkOnlyFaults leaves the transfer uploading when the token
// cannot be drawn or stored.
func TestFinalizeLinkOnlyFaults(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	ev.allowLinkOnly(t, ev.a, true)
	d := ev.mustCreate(t, internalSender(), linkOnlyRequest())
	ev.complete(t, d.ID, "")
	ev.svc.newDownloadToken = func() (string, error) { return "", errFault }
	if _, err := ev.svc.Finalize(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, errFault) {
		t.Errorf("token: %v", err)
	}
	ev.svc.newDownloadToken = id.NewDownloadToken
	ev.faults().fail["setLinkOnlyToken"] = errFault
	if _, err := ev.svc.Finalize(ctx, ev.a, internalSender(), d.ID); !errors.Is(err, errFault) {
		t.Errorf("store: %v", err)
	}
	got, err := ev.db.Transfers().Get(ctx, ev.a.ID, d.ID)
	if err != nil || got.Status != store.TransferUploading || len(got.DownloadTokenHash) != 0 {
		t.Errorf("after faults: %q %x %v", got.Status, got.DownloadTokenHash, err)
	}
}

// TestFingerprintLinkOnly keeps the fingerprint of a request without the
// option and changes it with it.
func TestFingerprintLinkOnly(t *testing.T) {
	t.Parallel()
	req := request()
	p := plan{recipients: []string{dave}}
	lo := req
	lo.LinkOnly = true
	if fingerprint(p, req) == fingerprint(p, lo) {
		t.Error("linkOnly does not change the fingerprint")
	}
}
