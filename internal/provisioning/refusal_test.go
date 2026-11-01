package provisioning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenantadmin"
)

// refusalReasons returns the reason codes of the tenant.provision_refused
// events, oldest first, checking the fields every one of them must carry.
func (ev *env) refusalReasons(t *testing.T, tokID string) []string {
	t.Helper()
	var out []string
	for _, e := range ev.auditEvents(t, ActionTenantProvisionRefused) {
		if e.TenantID != "" || e.ActorKind != store.ActorProvisioningToken || e.Actor != tokID ||
			e.ObjectKind != objectToken || e.ObjectID != tokID || e.IP != mspIP {
			t.Errorf("refusal event %+v", e)
		}
		var d map[string]string
		if err := json.Unmarshal(e.Details, &d); err != nil || len(d) != 1 {
			t.Errorf("refusal details %s: %v", e.Details, err)
		}
		out = append(out, d["reason"])
	}
	return out
}

// TestProvisionTenantRefusalAudit checks that every refused creation is
// recorded with its reason code only (T-270), and that a creation is not.
func TestProvisionTenantRefusalAudit(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		tok := ev.mustToken(t, goodCreate())
		p := ev.mustAuth(t, tok.Secret)
		if _, err := ev.svc.ProvisionTenant(ctx, p, request("a.transfer.example.com", "a.admin"), mspIP); err != nil {
			t.Fatal(err)
		}
		// Username taken (409), outside the scope (403), malformed (400).
		_, err := ev.svc.ProvisionTenant(ctx, p, request("b.transfer.example.com", "a.admin"), mspIP)
		wantErr(t, "username taken", err, tenantadmin.ErrAlreadyExists)
		_, err = ev.svc.ProvisionTenant(ctx, p, request("b.other.example.com", "b.admin"), mspIP)
		wantErr(t, "scope", err, ErrScopeExceeded)
		_, err = ev.svc.ProvisionTenant(ctx, p, request("not a host", "b.admin"), mspIP)
		wantErr(t, "invalid", err, ErrInvalid)
		got := ev.refusalReasons(t, tok.ID)
		want := []string{RefusalAlreadyExists, RefusalScopeExceeded, RefusalInvalid}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("reasons = %v, want %v", got, want)
		}
		for _, e := range ev.auditEvents(t, ActionTenantProvisionRefused) {
			if strings.Contains(string(e.Details), "a.admin") {
				t.Errorf("username recorded: %+v", e.Details)
			}
		}
	})
}

// TestProvisionTenantAttemptLimit checks the per-token limit on every
// creation attempt (T-273): refusals count, the 31st attempt within an
// hour answers 429 whatever it carries, other tokens are not affected,
// and the rate-limited attempts are recorded at most once a minute.
func TestProvisionTenantAttemptLimit(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	tok := ev.mustToken(t, goodCreate())
	p := ev.mustAuth(t, tok.Secret)
	other := ev.mustAuth(t, ev.mustToken(t, goodCreate()).Secret)
	outside := request("x.other.example.com", "x.admin")
	for i := range AttemptsPerHour {
		if _, err := ev.svc.ProvisionTenant(ctx, p, outside, mspIP); !errors.Is(err, ErrScopeExceeded) {
			t.Fatalf("attempt %d: %v", i, err)
		}
		ev.clock.Advance(time.Second)
	}
	_, err := ev.svc.ProvisionTenant(ctx, p, request("a.transfer.example.com", "a.admin"), mspIP)
	var rl *RateLimitError
	if !errors.As(err, &rl) || !errors.Is(err, ErrRateLimited) || rl.RetryAfter <= 0 || rl.RetryAfter > AttemptWindow {
		t.Fatalf("over the limit: %v", err)
	}
	// A second refusal within the minute is not recorded again.
	ev.clock.Advance(30 * time.Second)
	_, err = ev.svc.ProvisionTenant(ctx, p, outside, mspIP)
	wantErr(t, "still limited", err, ErrRateLimited)
	ev.clock.Advance(RefusalAuditInterval)
	_, err = ev.svc.ProvisionTenant(ctx, p, outside, mspIP)
	wantErr(t, "limited after a minute", err, ErrRateLimited)
	reasons := ev.refusalReasons(t, tok.ID)
	if len(reasons) != AttemptsPerHour+2 || reasons[AttemptsPerHour] != RefusalRateLimited ||
		reasons[AttemptsPerHour+1] != RefusalRateLimited {
		t.Errorf("reasons = %v", reasons)
	}
	// Another token keeps its own count.
	if _, err := ev.svc.ProvisionTenant(ctx, other, request("b.transfer.example.com", "b.admin"), mspIP); err != nil {
		t.Errorf("other token: %v", err)
	}
	// Once the window has passed, the token may create again.
	ev.clock.Advance(AttemptWindow)
	if _, err := ev.svc.ProvisionTenant(ctx, p, request("a.transfer.example.com", "a.admin"), mspIP); err != nil {
		t.Errorf("after the window: %v", err)
	}
}

// TestProvisionTenantRefusalAuditFailure checks that a failed refusal
// audit is logged and does not change the answer, and that an internal
// failure is not recorded as a refusal.
func TestProvisionTenantRefusalAuditFailure(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	tok := ev.mustToken(t, goodCreate())
	p := ev.mustAuth(t, tok.Secret)
	ev.faults("record")
	_, err := ev.svc.ProvisionTenant(ctx, p, request("x.other.example.com", "x.admin"), mspIP)
	wantErr(t, "scope", err, ErrScopeExceeded)
	if logs := ev.logs.String(); !strings.Contains(logs, "audit write failed") ||
		!strings.Contains(logs, string(ActionTenantProvisionRefused)) {
		t.Errorf("logs = %s", logs)
	}
	ev.faults()
	ev.svc.tenants = fakeProvisioner{err: errBoom}
	_, err = ev.svc.ProvisionTenant(ctx, p, request("a.transfer.example.com", "a.admin"), mspIP)
	wantErr(t, "internal", err, errBoom)
	if got := ev.refusalReasons(t, tok.ID); len(got) != 0 {
		t.Errorf("reasons = %v", got)
	}
}

// TestProvisionTenantTokenUnusable checks a token revoked or expired
// between its authentication and the creation: refused with the reason
// revoked_or_expired in the log (never "revoked" for an expired one) and
// token_unusable in the audit.
func TestProvisionTenantTokenUnusable(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	in := goodCreate()
	expires := testStart.Add(time.Hour)
	in.ExpiresAt = &expires
	tok := ev.mustToken(t, in)
	p := ev.mustAuth(t, tok.Secret)
	ev.clock.Advance(2 * time.Hour)
	_, err := ev.svc.ProvisionTenant(ctx, p, request("a.transfer.example.com", "a.admin"), mspIP)
	wantReason(t, "expired since", err, ReasonUnusable)
	if logs := ev.logs.String(); !strings.Contains(logs, "provisioning token refused at tenant creation") ||
		!strings.Contains(logs, "reason="+ReasonUnusable) || strings.Contains(logs, "reason="+ReasonRevoked+"\n") {
		t.Errorf("logs = %s", logs)
	}
	if got := ev.refusalReasons(t, tok.ID); len(got) != 1 || got[0] != RefusalTokenUnusable {
		t.Errorf("reasons = %v", got)
	}
}

func TestRefusalReason(t *testing.T) {
	t.Parallel()
	for err, want := range map[error]string{
		&RateLimitError{RetryAfter: time.Second}:             RefusalRateLimited,
		&ScopeError{Field: FieldFQDN}:                        RefusalScopeExceeded,
		refuse(ReasonUnusable, "prv_x"):                      RefusalTokenUnusable,
		tenantadmin.ErrAlreadyExists:                         RefusalAlreadyExists,
		tenantadmin.ErrUnknownBackgroundPreset:               RefusalUnknownBackgroundPreset,
		adminauth.ErrSystemSMTPUnavailable:                   RefusalSystemSMTPUnavailable,
		invalid(FieldFQDN, "x"):                              RefusalInvalid,
		fmt.Errorf("w: %w", tenantadmin.ErrInvalid):          RefusalInvalid,
		&adminauth.InvalidError{Field: adminauth.FieldEmail}: RefusalInvalid,
		errBoom: "",
	} {
		if got := refusalReason(err); got != want {
			t.Errorf("refusalReason(%v) = %q, want %q", err, got, want)
		}
	}
}
