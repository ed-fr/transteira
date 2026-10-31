package tenantadmin

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/textproposals"
)

const hostS = "transfer.entity-s.example.com"

// Texts of the legal documents used by the setup tests.
const (
	writtenNotice = "# Legal notice\n\nEntity S, 1 example street."
	markedNotice  = "# Legal notice\n\n[To complete: company name]"
)

// setupEnv is an env with a tenant S in setup and its delegated admin.
type setupEnv struct {
	*env
	s      *tenant.Tenant
	adminS adminauth.Principal
}

func newSetupEnv(t *testing.T, e storetest.Engine, opts ...envOption) *setupEnv {
	t.Helper()
	ev := newEnv(t, e, opts...)
	s, err := ev.db.Tenants().Create(context.Background(), &tenant.Tenant{
		SetupState: tenant.SetupStateSetup, Name: "Entity S", FQDN: hostS, DefaultLanguage: "en",
		MaxTransferBytes: 10 << 30, StorageQuotaBytes: 100 << 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &setupEnv{env: ev, s: s, adminS: principal(store.RoleDelegatedAdmin, "sam", s.ID)}
}

// configure does every required item of the checklist of S.
func (ev *setupEnv) configure(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	_, err := ev.svc.UpdateNetworkRules(ctx, ev.adminS, ev.s.ID, []string{"10.0.0.0/8"}, []string{"entity-s.example.com"}, clientIP)
	mustNoErr(t, "network", err)
	ev.setSMTP(t, "smtp-relay")
	ev.testSMTP(t)
	for _, doc := range []string{store.LegalNotice, store.PrivacyPolicy} {
		_, err := ev.svc.UpdateLegal(ctx, ev.adminS, ev.s.ID, doc, "en", writtenNotice, clientIP)
		mustNoErr(t, "legal "+doc, err)
	}
}

func (ev *setupEnv) setSMTP(t *testing.T, host string) {
	t.Helper()
	_, err := ev.svc.UpdateSMTP(context.Background(), ev.adminS, ev.s.ID, SMTPUpdate{
		Host: host, Port: 25, Security: store.SMTPSecurityNone, FromAddress: "noreply@entity-s.example.com",
	}, clientIP)
	mustNoErr(t, "smtp", err)
}

func (ev *setupEnv) testSMTP(t *testing.T) SMTPTestResult {
	t.Helper()
	res, err := ev.svc.TestSMTP(context.Background(), ev.adminS, ev.s.ID, "admin@entity-s.example.com", clientIP)
	mustNoErr(t, "smtp test", err)
	return res
}

// detailsOf decodes the details of an audit event.
func detailsOf(t *testing.T, e store.AuditEvent) map[string]any {
	t.Helper()
	var d map[string]any
	mustNoErr(t, "details", json.Unmarshal(e.Details, &d))
	return d
}

// done returns the done flags of the checklist by key.
func done(s Setup) map[string]bool {
	out := map[string]bool{}
	for _, it := range s.Items {
		out[it.Key] = it.Done
	}
	return out
}

func (ev *setupEnv) setup(t *testing.T) Setup {
	t.Helper()
	s, err := ev.svc.GetSetup(context.Background(), ev.adminS, ev.s.ID)
	mustNoErr(t, "get setup", err)
	return s
}

func TestGetSetupChecklist(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newSetupEnv(t, e)

		// A new tenant: nothing done, in the documented order.
		got := ev.setup(t)
		want := Setup{State: tenant.SetupStateSetup, Items: []SetupItem{
			{Key: SetupBrandingLogo},
			{Key: SetupBrandingColors},
			{Key: SetupSMTP, Required: true},
			{Key: SetupInternalNetworks, Required: true},
			{Key: SetupInternalDomains, Required: true},
			{Key: SetupLegalNotice, Required: true},
			{Key: SetupPrivacyPolicy, Required: true},
			{Key: SetupMailTemplates},
		}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("GetSetup = %+v, want %+v", got, want)
		}

		// Network rules, one list at a time.
		_, err := ev.svc.UpdateNetworkRules(ctx, ev.adminS, ev.s.ID, []string{"10.0.0.0/8"}, nil, clientIP)
		mustNoErr(t, "network", err)
		if d := done(ev.setup(t)); !d[SetupInternalNetworks] || d[SetupInternalDomains] {
			t.Errorf("after the ranges: %v", d)
		}
		_, err = ev.svc.UpdateNetworkRules(ctx, ev.adminS, ev.s.ID, nil, []string{"entity-s.example.com"}, clientIP)
		mustNoErr(t, "network", err)
		if d := done(ev.setup(t)); d[SetupInternalNetworks] || !d[SetupInternalDomains] {
			t.Errorf("after the domains: %v", d)
		}
		_, err = ev.svc.UpdateNetworkRules(ctx, ev.adminS, ev.s.ID, []string{"10.0.0.0/8"}, []string{"entity-s.example.com"}, clientIP)
		mustNoErr(t, "network", err)

		// SMTP: configured is not enough, a failed test neither.
		ev.setSMTP(t, "smtp-relay")
		if done(ev.setup(t))[SetupSMTP] {
			t.Error("smtp done before any test")
		}
		ev.mailer.err = errors.New("connect: refused")
		if res := ev.testSMTP(t); res.Success || done(ev.setup(t))[SetupSMTP] {
			t.Errorf("failed test counted: %+v", res)
		}
		ev.mailer.err = nil
		if res := ev.testSMTP(t); !res.Success || !done(ev.setup(t))[SetupSMTP] {
			t.Errorf("successful test not counted: %+v", res)
		}
		// Any change of the settings, even to the same values, undoes it.
		ev.setSMTP(t, "smtp-relay")
		if done(ev.setup(t))[SetupSMTP] {
			t.Error("smtp still done after a change")
		}
		ev.testSMTP(t)
		ev.setSMTP(t, "smtp-relay-2")
		if done(ev.setup(t))[SetupSMTP] {
			t.Error("smtp still done after a change of host")
		}
		ev.testSMTP(t)
		if !done(ev.setup(t))[SetupSMTP] {
			t.Error("smtp not done after a new test")
		}

		// Legal documents: in the default language, without marker.
		_, err = ev.svc.UpdateLegal(ctx, ev.adminS, ev.s.ID, store.LegalNotice, "fr", writtenNotice, clientIP)
		mustNoErr(t, "legal fr", err)
		_, err = ev.svc.UpdateLegal(ctx, ev.adminS, ev.s.ID, store.LegalNotice, "en", markedNotice, clientIP)
		mustNoErr(t, "legal marked", err)
		if d := done(ev.setup(t)); d[SetupLegalNotice] || d[SetupPrivacyPolicy] {
			t.Errorf("marked or foreign-language document counted: %v", d)
		}
		_, err = ev.svc.UpdateLegal(ctx, ev.adminS, ev.s.ID, store.LegalNotice, "en", writtenNotice, clientIP)
		mustNoErr(t, "legal", err)
		_, err = ev.svc.UpdateLegal(ctx, ev.adminS, ev.s.ID, store.PrivacyPolicy, "en", writtenNotice, clientIP)
		mustNoErr(t, "privacy", err)
		got = ev.setup(t)
		if d := done(got); !d[SetupLegalNotice] || !d[SetupPrivacyPolicy] || !got.CanComplete {
			t.Errorf("all required items: %+v", got)
		}

		// Optional items: colors (either one), logo.
		if d := done(got); d[SetupBrandingColors] || d[SetupBrandingLogo] || d[SetupMailTemplates] {
			t.Errorf("optional items done: %v", d)
		}
		_, err = ev.svc.UpdateBranding(ctx, ev.adminS, ev.s.ID, strings.ToLower(tenant.DefaultPrimaryColor), "#112233", clientIP)
		mustNoErr(t, "branding", err)
		cur, err := ev.db.Tenants().Get(ctx, ev.s.ID)
		mustNoErr(t, "get", err)
		cur.HasLogo = true
		_, err = ev.db.Tenants().Update(ctx, cur)
		mustNoErr(t, "logo", err)
		if d := done(ev.setup(t)); !d[SetupBrandingColors] || !d[SetupBrandingLogo] {
			t.Errorf("branding items: %v", d)
		}
		_, err = ev.svc.UpdateBranding(ctx, ev.adminS, ev.s.ID, tenant.DefaultPrimaryColor, strings.ToLower(tenant.DefaultAccentColor), clientIP)
		mustNoErr(t, "branding", err)
		if done(ev.setup(t))[SetupBrandingColors] {
			t.Error("default colors counted as changed")
		}

		// Access: super admin yes; another tenant's admin and anonymous no.
		if _, err := ev.svc.GetSetup(ctx, ev.super, ev.s.ID); err != nil {
			t.Errorf("super admin: %v", err)
		}
		_, err = ev.svc.GetSetup(ctx, ev.adminA, ev.s.ID)
		wantErr(t, "foreign tenant", err, ErrNotFound)
		_, err = ev.svc.GetSetup(ctx, ev.adminA, tenant.ID(id.New(id.Tenant)))
		wantErr(t, "unknown tenant", err, ErrNotFound)
		_, err = ev.svc.GetSetup(ctx, adminauth.Principal{}, ev.s.ID)
		wantErr(t, "unauthenticated", err, ErrUnauthenticated)

		// An active tenant keeps its checklist.
		a, err := ev.svc.GetSetup(ctx, ev.adminA, ev.a.ID)
		if err != nil || a.State != tenant.SetupStateActive || a.CanComplete {
			t.Errorf("active tenant: %+v, %v", a, err)
		}
	})
}

func TestCompleteSetup(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newSetupEnv(t, e)

		// Incomplete: every required item listed, nothing changed.
		_, err := ev.svc.CompleteSetup(ctx, ev.adminS, ev.s.ID, false, true, clientIP)
		var inc *IncompleteError
		if !errors.As(err, &inc) || !errors.Is(err, ErrSetupIncomplete) || inc.Error() == "" ||
			!reflect.DeepEqual(inc.Missing, []string{SetupSMTP, SetupInternalNetworks, SetupInternalDomains, SetupLegalNotice, SetupPrivacyPolicy}) {
			t.Fatalf("incomplete: %v", err)
		}
		// Forcing is the super admin's only; access is checked first.
		_, err = ev.svc.CompleteSetup(ctx, ev.adminS, ev.s.ID, true, false, clientIP)
		wantErr(t, "delegated force", err, ErrForbidden)
		_, err = ev.svc.CompleteSetup(ctx, ev.adminA, ev.s.ID, true, false, clientIP)
		wantErr(t, "foreign tenant", err, ErrNotFound)
		_, err = ev.svc.CompleteSetup(ctx, ev.adminA, ev.s.ID, false, false, clientIP)
		wantErr(t, "foreign tenant", err, ErrNotFound)
		_, err = ev.svc.CompleteSetup(ctx, adminauth.Principal{}, ev.s.ID, false, false, clientIP)
		wantErr(t, "unauthenticated", err, ErrUnauthenticated)
		if got, _ := ev.db.Tenants().Get(ctx, ev.s.ID); got.SetupState != tenant.SetupStateSetup {
			t.Fatalf("a refused completion changed the state: %+v", got)
		}
		if len(ev.auditEvents(t, ev.s.ID, ActionTenantSetupCompleted)) != 0 {
			t.Fatal("refusals audited as completions")
		}

		// Complete: active, review recorded, cache invalidated, audited.
		ev.configure(t)
		got, err := ev.svc.CompleteSetup(ctx, ev.adminS, ev.s.ID, false, true, clientIP)
		mustNoErr(t, "complete", err)
		if got.State != tenant.SetupStateActive || !got.CanComplete || !done(got)[SetupMailTemplates] {
			t.Fatalf("completed: %+v", got)
		}
		if stored, _ := ev.db.Tenants().Get(ctx, ev.s.ID); stored.SetupState != tenant.SetupStateActive ||
			!stored.MailTemplatesReviewedAt.Equal(testStart) {
			t.Fatalf("stored: %+v", stored)
		}
		if !ev.cache.sawHost(hostS) {
			t.Error("the resolution cache was not invalidated")
		}
		evs := ev.auditEvents(t, ev.s.ID, ActionTenantSetupCompleted)
		if len(evs) != 1 || evs[0].Actor != "sam" || evs[0].IP != clientIP || detailsOf(t, evs[0])["forced"] != false ||
			detailsOf(t, evs[0])["missing"] != nil {
			t.Fatalf("audit: %+v", evs)
		}
		// No way back.
		_, err = ev.svc.CompleteSetup(ctx, ev.adminS, ev.s.ID, false, false, clientIP)
		wantErr(t, "again", err, ErrSetupComplete)
		_, err = ev.svc.CompleteSetup(ctx, ev.super, ev.s.ID, true, false, clientIP)
		wantErr(t, "again forced", err, ErrSetupComplete)
	})
}

func TestCompleteSetupForced(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newSetupEnv(t, e)
		got, err := ev.svc.CompleteSetup(ctx, ev.super, ev.s.ID, true, false, clientIP)
		mustNoErr(t, "forced", err)
		if got.State != tenant.SetupStateActive || got.CanComplete || done(got)[SetupMailTemplates] {
			t.Fatalf("forced: %+v", got)
		}
		evs := ev.auditEvents(t, ev.s.ID, ActionTenantSetupCompleted)
		if len(evs) != 1 || evs[0].Actor != "root" || detailsOf(t, evs[0])["forced"] != true {
			t.Fatalf("audit: %+v", evs)
		}
		missing, _ := detailsOf(t, evs[0])["missing"].([]any)
		if len(missing) != 5 || missing[0] != SetupSMTP {
			t.Errorf("missing items audited: %v", detailsOf(t, evs[0])["missing"])
		}
	})
}

// Forced with every item done: no missing list in the audit.
func TestCompleteSetupForcedComplete(t *testing.T) {
	ctx := context.Background()
	ev := newSetupEnv(t, storetest.SQLite(t))
	ev.configure(t)
	_, err := ev.svc.CompleteSetup(ctx, ev.super, ev.s.ID, true, false, clientIP)
	mustNoErr(t, "forced complete", err)
	evs := ev.auditEvents(t, ev.s.ID, ActionTenantSetupCompleted)
	if len(evs) != 1 || detailsOf(t, evs[0])["forced"] != true || detailsOf(t, evs[0])["missing"] != nil {
		t.Fatalf("audit: %+v", evs)
	}
}

// raceRepo runs before ahead of the completion statement, to change the
// configuration between the checks of the service and the statement.
type raceRepo struct {
	repo
	before func()
}

func (r *raceRepo) completeSetup(ctx context.Context, tid tenant.ID, force bool, reviewedAt time.Time) (*tenant.Tenant, error) {
	r.before()
	return r.repo.completeSetup(ctx, tid, force, reviewedAt)
}

// An SMTP change committed between the checklist and the completion makes
// the statement fail: the checklist is computed again (T-262).
func TestCompleteSetupSMTPRace(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newSetupEnv(t, e)
		ev.configure(t)
		inner := ev.svc.repo
		ev.svc.repo = &raceRepo{repo: inner, before: func() { ev.setSMTP(t, "smtp-other") }}
		_, err := ev.svc.CompleteSetup(ctx, ev.adminS, ev.s.ID, false, false, clientIP)
		var inc *IncompleteError
		if !errors.As(err, &inc) || !reflect.DeepEqual(inc.Missing, []string{SetupSMTP}) {
			t.Fatalf("race: %v", err)
		}
		if got, _ := ev.db.Tenants().Get(ctx, ev.s.ID); got.SetupState != tenant.SetupStateSetup {
			t.Fatalf("completed despite the change: %+v", got)
		}
		// The network rules removed meanwhile: refused by the statement too.
		ev.testSMTP(t)
		ev.svc.repo = &raceRepo{repo: inner, before: func() {
			if _, err := ev.db.NetworkRules().Replace(ctx, ev.s.ID, nil, nil); err != nil {
				t.Error(err)
			}
		}}
		_, err = ev.svc.CompleteSetup(ctx, ev.adminS, ev.s.ID, false, false, clientIP)
		if !errors.As(err, &inc) || !reflect.DeepEqual(inc.Missing, []string{SetupInternalNetworks, SetupInternalDomains}) {
			t.Fatalf("network race: %v", err)
		}
		_, err = ev.svc.UpdateNetworkRules(ctx, ev.adminS, ev.s.ID, []string{"10.0.0.0/8"}, []string{"entity-s.example.com"}, clientIP)
		mustNoErr(t, "network", err)
		// Tested again in the meantime: the checklist is complete, the SMTP
		// item is still reported (the caller retries).
		ev.svc.repo = &raceRepo{repo: inner, before: func() {}}
		ev.testSMTP(t)
		f := ev.faults()
		f.errs["completeSetup"] = store.ErrConflict
		_, err = ev.svc.CompleteSetup(ctx, ev.adminS, ev.s.ID, false, false, clientIP)
		if !errors.As(err, &inc) || !reflect.DeepEqual(inc.Missing, []string{SetupSMTP}) {
			t.Fatalf("conflict with a complete checklist: %v", err)
		}
		// Completed by someone else meanwhile.
		ev.svc.repo = &raceRepo{repo: inner, before: func() {
			if _, err := ev.db.Tenants().CompleteSetup(ctx, ev.s.ID, true, time.Time{}); err != nil {
				t.Error(err)
			}
		}}
		_, err = ev.svc.CompleteSetup(ctx, ev.adminS, ev.s.ID, false, false, clientIP)
		wantErr(t, "completed meanwhile", err, ErrSetupComplete)
	})
}

func TestCompleteSetupConflictCompletedMeanwhile(t *testing.T) {
	ctx := context.Background()
	ev := newSetupEnv(t, storetest.SQLite(t))
	ev.configure(t)
	inner := ev.svc.repo
	// The statement reports a conflict while another admin completed it.
	ev.svc.repo = &conflictRepo{repo: inner, then: func() {
		if _, err := ev.db.Tenants().CompleteSetup(ctx, ev.s.ID, true, time.Time{}); err != nil {
			t.Error(err)
		}
	}}
	_, err := ev.svc.CompleteSetup(ctx, ev.adminS, ev.s.ID, false, false, clientIP)
	wantErr(t, "completed meanwhile", err, ErrSetupComplete)
}

// conflictRepo answers ErrConflict to the completion after running then.
type conflictRepo struct {
	repo
	then func()
}

func (r *conflictRepo) completeSetup(context.Context, tenant.ID, bool, time.Time) (*tenant.Tenant, error) {
	r.then()
	return nil, store.ErrConflict
}

func TestSetupFaults(t *testing.T) {
	ctx := context.Background()
	ev := newSetupEnv(t, storetest.SQLite(t))
	ev.configure(t)

	// The checklist reads.
	for _, m := range []string{"smtp", "networkRules", "legal"} {
		ev.faults(m)
		_, err := ev.svc.GetSetup(ctx, ev.adminS, ev.s.ID)
		wantErr(t, "get setup, "+m, err, errBoom)
		_, err = ev.svc.CompleteSetup(ctx, ev.adminS, ev.s.ID, false, false, clientIP)
		wantErr(t, "complete, "+m, err, errBoom)
	}
	// The second legal document.
	f := ev.faults("legal")
	f.after["legal"] = 1
	_, err := ev.svc.GetSetup(ctx, ev.adminS, ev.s.ID)
	wantErr(t, "get setup, privacy policy", err, errBoom)
	ev.faults("getTenant")
	_, err = ev.svc.GetSetup(ctx, ev.adminS, ev.s.ID)
	wantErr(t, "get setup, tenant", err, errBoom)

	// The completion statement.
	ev.faults("completeSetup")
	_, err = ev.svc.CompleteSetup(ctx, ev.adminS, ev.s.ID, false, false, clientIP)
	wantErr(t, "complete, statement", err, errBoom)
	f = ev.faults()
	f.errs["completeSetup"] = store.ErrNotFound
	_, err = ev.svc.CompleteSetup(ctx, ev.adminS, ev.s.ID, false, false, clientIP)
	wantErr(t, "complete, gone", err, ErrNotFound)
	f.errs["completeSetup"] = store.ErrSetupComplete
	_, err = ev.svc.CompleteSetup(ctx, ev.adminS, ev.s.ID, false, false, clientIP)
	wantErr(t, "complete, already", err, ErrSetupComplete)

	// The recomputation after a conflict.
	f = ev.faults()
	f.errs["completeSetup"] = store.ErrConflict
	f.errs["getTenant"] = errBoom
	f.after["getTenant"] = 1 // the access check passes, the recomputation fails
	_, err = ev.svc.CompleteSetup(ctx, ev.adminS, ev.s.ID, false, false, clientIP)
	wantErr(t, "recompute, tenant", err, errBoom)
	f = ev.faults()
	f.errs["completeSetup"] = store.ErrConflict
	f.errs["networkRules"] = errBoom
	f.after["networkRules"] = 1
	_, err = ev.svc.CompleteSetup(ctx, ev.adminS, ev.s.ID, false, false, clientIP)
	wantErr(t, "recompute, checklist", err, errBoom)

	// The checklist answered after the completion.
	f = ev.faults("networkRules")
	f.after["networkRules"] = 1
	_, err = ev.svc.CompleteSetup(ctx, ev.adminS, ev.s.ID, false, false, clientIP)
	wantErr(t, "complete, final checklist", err, errBoom)
	if got, _ := ev.db.Tenants().Get(ctx, ev.s.ID); got.SetupState != tenant.SetupStateActive {
		t.Fatalf("not completed: %+v", got)
	}
}

// A successful SMTP test that cannot be recorded is still a success; the
// failure is logged.
func TestSMTPTestRecordFailure(t *testing.T) {
	ev := newSetupEnv(t, storetest.SQLite(t))
	ev.setSMTP(t, "smtp-relay")
	ev.faults("setSMTPTested")
	if res := ev.testSMTP(t); !res.Success {
		t.Fatalf("result %+v", res)
	}
	if !strings.Contains(ev.logs.String(), "recording the smtp test failed") {
		t.Errorf("not logged: %s", ev.logs.String())
	}
	ev.faults()
	if done(ev.setup(t))[SetupSMTP] {
		t.Error("an unrecorded test counted")
	}
}

func TestTextProposal(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newSetupEnv(t, e)
		for _, doc := range []string{store.LegalNotice, store.PrivacyPolicy} {
			for _, lang := range []string{"en", "fr"} {
				p, err := ev.svc.TextProposal(ctx, ev.adminS, ev.s.ID, doc, lang)
				mustNoErr(t, doc+" "+lang, err)
				if p.Document != doc || p.Language != lang || p.Notice != textproposals.NoticeKey ||
					!strings.Contains(p.Markdown, "Entity S") || !textproposals.HasPlaceholder(p.Markdown) {
					t.Errorf("%s %s: %+v", doc, lang, p)
				}
			}
		}
		p, err := ev.svc.TextProposal(ctx, ev.super, ev.s.ID, store.PrivacyPolicy, "en")
		mustNoErr(t, "super", err)
		if !strings.Contains(p.Markdown, "1, 7 and 30 days") || !strings.Contains(p.Markdown, "antivirus") ||
			strings.Count(p.Markdown, "12 months") != 3 {
			t.Errorf("facts missing: %s", p.Markdown)
		}

		// The durations come from the confidentiality levels.
		_, err = ev.svc.UpdateConfidentialityLevels(ctx, ev.adminS, ev.s.ID, []ConfidentialityLevel{{
			Key: "open", Labels: map[string]string{"en": "Open", "fr": "Ouvert"}, IsDefault: true,
			Rules: ConfidentialityRules{AllowedExpiryDays: []int{1, 7}},
		}, {
			Key: "short", Labels: map[string]string{"en": "Short", "fr": "Court"},
			Rules: ConfidentialityRules{AllowedExpiryDays: []int{1}},
		}}, clientIP)
		mustNoErr(t, "levels", err)
		p, err = ev.svc.TextProposal(ctx, ev.adminS, ev.s.ID, store.PrivacyPolicy, "en")
		mustNoErr(t, "proposal", err)
		if !strings.Contains(p.Markdown, "1 and 7 days") || strings.Contains(p.Markdown, "30 days") {
			t.Errorf("durations: %s", p.Markdown)
		}

		// Unknown document or language, foreign or unknown tenant: 404.
		for _, c := range [][2]string{{"terms", "en"}, {store.LegalNotice, "de"}, {"", ""}} {
			_, err := ev.svc.TextProposal(ctx, ev.adminS, ev.s.ID, c[0], c[1])
			wantErr(t, "unknown "+c[0]+" "+c[1], err, ErrNotFound)
		}
		_, err = ev.svc.TextProposal(ctx, ev.adminA, ev.s.ID, store.LegalNotice, "en")
		wantErr(t, "foreign tenant", err, ErrNotFound)
		_, err = ev.svc.TextProposal(ctx, ev.adminA, tenant.ID(id.New(id.Tenant)), store.LegalNotice, "en")
		wantErr(t, "unknown tenant", err, ErrNotFound)
		_, err = ev.svc.TextProposal(ctx, adminauth.Principal{}, ev.s.ID, store.LegalNotice, "en")
		wantErr(t, "unauthenticated", err, ErrUnauthenticated)

		// Nothing is saved.
		if docs, err := ev.db.TenantLegalDocuments().List(ctx, ev.s.ID); err != nil || len(docs) != 0 {
			t.Errorf("legal documents %v, %v", docs, err)
		}
		ev.faults("confidentialityLevels")
		_, err = ev.svc.TextProposal(ctx, ev.adminS, ev.s.ID, store.LegalNotice, "en")
		wantErr(t, "levels failure", err, errBoom)
		ev.faults()
		ev.svc.propose = func(string, string, textproposals.Facts) (string, error) { return "", textproposals.ErrUnknown }
		_, err = ev.svc.TextProposal(ctx, ev.adminS, ev.s.ID, store.LegalNotice, "en")
		if err == nil || errors.Is(err, ErrNotFound) || !errors.Is(err, textproposals.ErrUnknown) {
			t.Errorf("inconsistent lists: %v, want an internal error", err)
		}
	})
}

// Without antivirus engine, the proposal does not claim an analysis.
func TestTextProposalAntivirusDisabled(t *testing.T) {
	ev := newSetupEnv(t, storetest.SQLite(t), func(o *Options) { o.AntivirusDisabled = true })
	p, err := ev.svc.TextProposal(context.Background(), ev.adminS, ev.s.ID, store.PrivacyPolicy, "en")
	mustNoErr(t, "proposal", err)
	if strings.Contains(p.Markdown, "scanned by an antivirus") {
		t.Errorf("antivirus claimed: %s", p.Markdown)
	}
}
