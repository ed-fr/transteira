package transfer

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// intp returns &n.
func intp(n int) *int { return &n }

// strictLevels are the levels the policy tests install: "open" (default,
// no rule) and "secret" (every rule but the recipient verification, which
// cannot be satisfied until step 6).
func strictLevels() []store.ConfidentialityLevel {
	return []store.ConfidentialityLevel{
		{
			Key: "open", Labels: map[string]string{"fr": "Ouvert", "en": "Open"}, IsDefault: true,
			Rules: store.ConfidentialityRules{ExpiryDaysMask: store.ExpiryMaskAll},
		},
		{
			Key: "secret", Labels: map[string]string{"fr": "Secret", "en": "Secret EN"},
			Rules: store.ConfidentialityRules{
				ExpiryDaysMask: store.ExpiryMask1Day, MaxDownloadsCap: intp(5), RequirePassword: true,
				InternalRecipientsOnly: true, ForceDeleteAfterFirstDownload: true,
			},
		},
	}
}

// setLevels replaces the levels of tn.
func (ev *env) setLevels(t *testing.T, tn *tenant.Tenant, levels []store.ConfidentialityLevel) {
	t.Helper()
	if _, err := ev.db.ConfidentialityLevels().Replace(context.Background(), tn.ID, levels, "admin", ev.clock.Now()); err != nil {
		t.Fatalf("replace levels: %v", err)
	}
}

// setRecipientRules replaces the recipient domain rules of tn.
func (ev *env) setRecipientRules(t *testing.T, tn *tenant.Tenant, allowed, denied []string) {
	t.Helper()
	set := store.RecipientRuleSet{Allowed: allowed, Denied: denied}
	if _, err := ev.db.RecipientRules().Replace(context.Background(), tn.ID, set, ev.clock.Now()); err != nil {
		t.Fatalf("replace recipient rules: %v", err)
	}
}

// ruleFields returns the fields of a *RuleError of kind, failing otherwise.
func ruleFields(t *testing.T, err, kind error) []FieldError {
	t.Helper()
	var re *RuleError
	if !errors.As(err, &re) || !errors.Is(err, kind) {
		t.Fatalf("err = %v, want a rule error %v", err, kind)
	}
	return re.Fields
}

// transferCount returns the number of transfers of tn.
func (ev *env) transferCount(t *testing.T, tn *tenant.Tenant) int {
	t.Helper()
	page, err := ev.db.Transfers().AdminList(context.Background(), tn.ID, store.AdminTransferFilter{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	return len(page.Items)
}

func TestPickLevel(t *testing.T) {
	levels := strictLevels()
	if l, err := pickLevel(levels, ""); err != nil || l == nil || l.Key != "open" {
		t.Errorf("default = %+v, %v", l, err)
	}
	if l, err := pickLevel(levels, "secret"); err != nil || l == nil || l.Key != "secret" {
		t.Errorf("secret = %+v, %v", l, err)
	}
	_, err := pickLevel(levels, "nope")
	var verr *ValidationError
	if !errors.As(err, &verr) || !reflect.DeepEqual(verr.Fields, []FieldError{{Pointer: FieldConfidentialityLevel, Code: CodeNotAllowed}}) {
		t.Errorf("unknown = %v", err)
	}
	if l, err := pickLevel(nil, ""); l != nil || err != nil {
		t.Errorf("no levels = %+v, %v", l, err)
	}
	if _, err := pickLevel(nil, "secret"); err == nil {
		t.Error("unknown key without levels accepted")
	}
}

func TestCheckLevelRules(t *testing.T) {
	secret := &strictLevels()[1]
	rules := netpolicy.Rules{Domains: []string{"entity-a.example.com"}}
	pw := "pw"
	req := CreateRequest{ExpiryDays: 1, Password: &pw, MaxDownloads: intp(5)}
	if got := checkLevelRules(secret, req, []string{carol}, rules); got != nil {
		t.Errorf("valid request = %+v", got)
	}
	if got := checkLevelRules(nil, CreateRequest{}, []string{dave}, rules); got != nil {
		t.Errorf("no level = %+v", got)
	}
	bad := CreateRequest{ExpiryDays: 7, MaxDownloads: intp(6)}
	want := []FieldError{
		{Pointer: FieldPassword, Code: CodeRequired},
		{Pointer: FieldExpiryDays, Code: CodeNotAllowed, Allowed: []int{1}},
		{Pointer: "/recipients/1", Code: CodeInternalOnly},
		{Pointer: "/recipients/2", Code: CodeInternalOnly},
		{Pointer: FieldMaxDownloads, Code: CodeMaxExceeded},
	}
	got := checkLevelRules(secret, bad, []string{carol, dave, "x@sub.entity-a.example.com"}, rules)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("broken rules = %+v, want %+v", got, want)
	}
	verif := &store.ConfidentialityLevel{Rules: store.ConfidentialityRules{
		ExpiryDaysMask: store.ExpiryMaskAll, RequireRecipientVerification: true,
	}}
	got = checkLevelRules(verif, CreateRequest{ExpiryDays: 30}, nil, rules)
	if !reflect.DeepEqual(got, []FieldError{{Pointer: FieldRecipientVerification, Code: CodeRequired}}) {
		t.Errorf("verification = %+v", got)
	}
	if got := checkLevelRules(verif, CreateRequest{ExpiryDays: 30, RecipientVerification: true}, nil, rules); got != nil {
		t.Errorf("verification given = %+v", got)
	}
}

func TestApplyLevel(t *testing.T) {
	secret := &strictLevels()[1]
	p := applyLevel(secret, CreateRequest{})
	if p.maxDownloads == nil || *p.maxDownloads != 5 || !p.deleteAfterFirstDownload || p.level != secret {
		t.Errorf("forced = %+v", p)
	}
	if p.maxDownloads == secret.Rules.MaxDownloadsCap {
		t.Error("the cap is shared with the level")
	}
	p = applyLevel(secret, CreateRequest{MaxDownloads: intp(2)})
	if *p.maxDownloads != 2 {
		t.Errorf("requested limit = %d", *p.maxDownloads)
	}
	open := &strictLevels()[0]
	if p := applyLevel(open, CreateRequest{DeleteAfterFirstDownload: true}); p.maxDownloads != nil || !p.deleteAfterFirstDownload {
		t.Errorf("open = %+v", p)
	}
	if p := applyLevel(nil, CreateRequest{MaxDownloads: intp(3)}); p.level != nil || *p.maxDownloads != 3 || p.deleteAfterFirstDownload {
		t.Errorf("no level = %+v", p)
	}
}

func TestRefusedRecipients(t *testing.T) {
	set := store.RecipientRuleSet{Denied: []string{"customer.example.net"}}
	fields, domains := refusedRecipients([]string{carol, dave, "x@sub.customer.example.net", "y@customer.example.net"}, set)
	want := []FieldError{
		{Pointer: "/recipients/1", Code: CodeDomainDenied},
		{Pointer: "/recipients/2", Code: CodeDomainDenied},
		{Pointer: "/recipients/3", Code: CodeDomainDenied},
	}
	if !reflect.DeepEqual(fields, want) || !reflect.DeepEqual(domains, []string{"customer.example.net", "sub.customer.example.net"}) {
		t.Errorf("refused = %+v %v", fields, domains)
	}
	fields, domains = refusedRecipients([]string{carol, "z@bad..example"}, store.RecipientRuleSet{Allowed: []string{"entity-a.example.com"}})
	if len(fields) != 1 || fields[0].Pointer != "/recipients/1" || !reflect.DeepEqual(domains, []string{"bad..example"}) {
		t.Errorf("allow list = %+v %v", fields, domains)
	}
	// Without any rule, a domain that does not normalize stays accepted.
	if fields, domains := refusedRecipients([]string{dave, "x@localhost", "y@foo_bar.example.com"}, store.RecipientRuleSet{}); fields != nil || len(domains) != 0 {
		t.Errorf("no rules = %+v %v", fields, domains)
	}
}

func TestCreateOptionsValidation(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	for _, c := range []struct {
		name string
		edit func(r *CreateRequest)
		want FieldError
	}{
		{"max downloads zero", func(r *CreateRequest) { r.MaxDownloads = intp(0) }, FieldError{Pointer: FieldMaxDownloads, Code: CodeNotAllowed}},
		{"max downloads above", func(r *CreateRequest) { r.MaxDownloads = intp(1001) }, FieldError{Pointer: FieldMaxDownloads, Code: CodeNotAllowed}},
		{"level malformed", func(r *CreateRequest) { r.ConfidentialityLevel = "Secret" }, FieldError{Pointer: FieldConfidentialityLevel, Code: CodeInvalidFormat}},
		{"level unknown", func(r *CreateRequest) { r.ConfidentialityLevel = "secret" }, FieldError{Pointer: FieldConfidentialityLevel, Code: CodeNotAllowed}},
	} {
		t.Run(c.name, func(t *testing.T) {
			req := request()
			c.edit(&req)
			_, err := ev.svc.Create(context.Background(), ev.a, internalSender(), req, "")
			var verr *ValidationError
			if !errors.As(err, &verr) || !reflect.DeepEqual(verr.Fields, []FieldError{c.want}) {
				t.Fatalf("err = %v, want %+v", err, c.want)
			}
		})
	}
	// The limits themselves are accepted.
	for _, n := range []int{1, store.MaxDownloadsLimit} {
		req := request()
		req.MaxDownloads = intp(n)
		if d := ev.mustCreate(t, internalSender(), req); d.MaxDownloads == nil || *d.MaxDownloads != n {
			t.Errorf("max downloads %d = %v", n, d.MaxDownloads)
		}
	}
}

func TestCreateDefaultLevelSnapshot(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		d := ev.mustCreate(t, internalSender(), request())
		// The seeded default level of a tenant is "internal", without rule.
		if d.ConfidentialityLevel != "internal" || d.ConfidentialityLabel != "Internal" || d.MaxDownloads != nil ||
			d.Rules == nil || d.Rules.ExpiryDaysMask != store.ExpiryMaskAll || d.DeleteAfterFirstDownload {
			t.Errorf("details = %+v rules %+v", d, d.Rules)
		}
		stored, err := ev.db.Transfers().Get(ctx, ev.a.ID, d.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(stored.ConfidentialityLabel, map[string]string{"fr": "Interne", "en": "Internal"}) {
			t.Errorf("stored label = %v", stored.ConfidentialityLabel)
		}
		// Tenant B (French by default) shows the French label.
		reqB := request()
		db, err := ev.svc.Create(ctx, ev.b, internalSender(), reqB, "")
		if err != nil {
			t.Fatal(err)
		}
		if db.ConfidentialityLabel != "Interne" {
			t.Errorf("label in B = %q", db.ConfidentialityLabel)
		}
	})
}

func TestCreateLevelRules(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		h := ev.withHooks(&auditSpy{writer: audit.New(ev.db)})
		ev.setLevels(t, ev.a, strictLevels())

		// Every broken rule at once, nothing created, nothing logged.
		req := request()
		req.ConfidentialityLevel, req.MaxDownloads = "secret", intp(6)
		_, err := ev.svc.Create(ctx, ev.a, internalSender(), req, "")
		want := []FieldError{
			{Pointer: FieldPassword, Code: CodeRequired},
			{Pointer: FieldExpiryDays, Code: CodeNotAllowed, Allowed: []int{1}},
			{Pointer: "/recipients/0", Code: CodeInternalOnly},
			{Pointer: FieldMaxDownloads, Code: CodeMaxExceeded},
		}
		if got := ruleFields(t, err, ErrConfidentialityRule); !reflect.DeepEqual(got, want) {
			t.Errorf("fields = %+v, want %+v", got, want)
		}
		if n := ev.transferCount(t, ev.a); n != 0 {
			t.Errorf("%d transfers created", n)
		}

		// A satisfying request gets the forced options and the cap.
		pw := "pw"
		req = request()
		req.ConfidentialityLevel, req.Recipients, req.ExpiryDays, req.Password = "secret", []string{carol}, 1, &pw
		req.Language = "fr"
		d := ev.mustCreate(t, internalSender(), req)
		if d.ConfidentialityLevel != "secret" || d.ConfidentialityLabel != "Secret" || d.MaxDownloads == nil ||
			*d.MaxDownloads != 5 || !d.DeleteAfterFirstDownload || d.Rules == nil || !d.Rules.RequirePassword ||
			d.Rules.MaxDownloadsCap == nil || *d.Rules.MaxDownloadsCap != 5 {
			t.Errorf("details = %+v rules %+v", d, d.Rules)
		}
		events, _, errs := h.audit.snapshot()
		if len(errs) != 0 || len(events) != 1 || events[0].Details["confidentialityLevel"] != "secret" {
			t.Errorf("audit = %+v %v", events, errs)
		}

		// The snapshot survives a change of the levels.
		changed := strictLevels()
		changed[1].Labels = map[string]string{"fr": "Renommé", "en": "Renamed"}
		changed[1].Rules = store.ConfidentialityRules{ExpiryDaysMask: store.ExpiryMaskAll}
		ev.setLevels(t, ev.a, changed)
		got, err := ev.svc.Get(ctx, ev.a, internalSender(), d.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, d) {
			t.Errorf("after replace = %+v, want %+v", got, d)
		}
		ev.setLevels(t, ev.a, strictLevels()[:1])
		if got, err := ev.svc.Get(ctx, ev.a, internalSender(), d.ID); err != nil || got.ConfidentialityLevel != "secret" {
			t.Errorf("after removal = %+v, %v", got, err)
		}

		// The levels of A never apply in B.
		req.Recipients = []string{carol}
		_, err = ev.svc.Create(ctx, ev.b, internalSender(), req, "")
		var verr *ValidationError
		if !errors.As(err, &verr) || verr.Fields[0].Pointer != FieldConfidentialityLevel {
			t.Errorf("secret in B = %v", err)
		}
		if len(ev.seclog.events) != 0 {
			t.Errorf("security events = %+v", ev.seclog.events)
		}
	})
}

func TestCreateSeededConfidentialNeedsVerification(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	pw := "pw"
	req := request()
	req.ConfidentialityLevel, req.Recipients, req.Password = "confidential", []string{carol}, &pw
	_, err := ev.svc.Create(context.Background(), ev.a, internalSender(), req, "")
	if got := ruleFields(t, err, ErrConfidentialityRule); !reflect.DeepEqual(got,
		[]FieldError{{Pointer: FieldRecipientVerification, Code: CodeRequired}}) {
		t.Errorf("fields = %+v", got)
	}
	// With the option, the seeded level is usable since step 6 of 1.1.
	req.RecipientVerification = true
	d, err := ev.svc.Create(context.Background(), ev.a, internalSender(), req, "")
	if err != nil {
		t.Fatal(err)
	}
	if !d.RecipientVerification || d.ConfidentialityLevel != "confidential" {
		t.Errorf("details = %+v", d)
	}
}

func TestCreatePerRecipientLinks(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		for _, verif := range []bool{false, true} {
			req := request()
			req.RecipientVerification = verif
			d := ev.mustCreate(t, internalSender(), req)
			if d.RecipientVerification != verif || d.DownloadURL != "" {
				t.Errorf("verification %v: details = %+v", verif, d)
			}
			stored, err := ev.db.Transfers().Get(ctx, ev.a.ID, d.ID)
			if err != nil {
				t.Fatal(err)
			}
			if stored.LinkMode != store.LinkModePerRecipient || stored.RecipientVerification != verif {
				t.Errorf("verification %v: stored mode %q verification %v", verif, stored.LinkMode, stored.RecipientVerification)
			}
		}
	})
}

func TestCreateCheckOrder(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		ev.setLevels(t, ev.a, strictLevels())
		ev.setRecipientRules(t, ev.a, nil, []string{"customer.example.net"})

		// 400 before 422: a shape error wins over the level rules.
		req := request()
		req.ConfidentialityLevel, req.MaxDownloads = "secret", intp(0)
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), req, ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("shape = %v", err)
		}
		// 422 before 403: the level rules win over the domain rules.
		req.MaxDownloads = nil
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), req, ""); !errors.Is(err, ErrConfidentialityRule) {
			t.Errorf("rules = %v", err)
		}
		// 403 before 413 and the quota.
		req = request()
		req.Files[0].Size = maxBytes + 1
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), req, ""); !errors.Is(err, ErrRecipientDomainRefused) {
			t.Errorf("domains = %v", err)
		}
	})
}

func TestCreateRecipientRules(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		h := ev.withHooks(&auditSpy{writer: audit.New(ev.db)})
		ev.setRecipientRules(t, ev.a, nil, []string{"customer.example.net"})

		req := request()
		req.Recipients = []string{carol, dave, "erin@sub.customer.example.net"}
		_, err := ev.svc.Create(ctx, ev.a, internalSender(), req, "")
		want := []FieldError{
			{Pointer: "/recipients/1", Code: CodeDomainDenied}, {Pointer: "/recipients/2", Code: CodeDomainDenied},
		}
		if got := ruleFields(t, err, ErrRecipientDomainRefused); !reflect.DeepEqual(got, want) {
			t.Errorf("fields = %+v", got)
		}
		events, tids, errs := h.audit.snapshot()
		if len(errs) != 0 || len(events) != 1 || tids[0] != ev.a.ID {
			t.Fatalf("audit = %+v %v %v", events, tids, errs)
		}
		ev0 := events[0]
		if ev0.Action != audit.ActionTransferRecipientRefused || ev0.Actor != alice || ev0.ActorKind != store.ActorDepositor ||
			ev0.ObjectKind != audit.ObjectTenant || ev0.ObjectID != ev.a.ID.String() || ev0.IP != internalIP ||
			!reflect.DeepEqual(ev0.Details["domains"], []string{"customer.example.net", "sub.customer.example.net"}) ||
			ev0.Details["origin"] != originInternal {
			t.Errorf("event = %+v", ev0)
		}
		// Never in the security log, nothing created.
		if len(ev.seclog.events) != 0 {
			t.Errorf("security events = %+v", ev.seclog.events)
		}
		if n := ev.transferCount(t, ev.a); n != 0 {
			t.Errorf("%d transfers created", n)
		}
		// The rules of A never apply in B.
		if _, err := ev.svc.Create(ctx, ev.b, internalSender(), req, ""); err != nil {
			t.Errorf("B: %v", err)
		}

		// A non-empty allow list accepts only its domains (and subdomains).
		ev.setRecipientRules(t, ev.a, []string{"entity-a.example.com"}, nil)
		req.Recipients = []string{"x@team.entity-a.example.com", dave}
		_, err = ev.svc.Create(ctx, ev.a, internalSender(), req, "")
		if got := ruleFields(t, err, ErrRecipientDomainRefused); len(got) != 1 || got[0].Pointer != "/recipients/1" {
			t.Errorf("allow list = %+v", got)
		}
		req.Recipients = []string{"x@team.entity-a.example.com", carol}
		ev.mustCreate(t, internalSender(), req)

		// Invitations: the only recipient is the inviter, not a free choice,
		// so the domain rules never apply to an invited external depositor.
		ev.setRecipientRules(t, ev.a, nil, []string{"entity-a.example.com"})
		if _, err := ev.svc.Create(ctx, ev.a, ev.external(), request(), ""); err != nil {
			t.Errorf("external with deny list: %v", err)
		}
		ev.setRecipientRules(t, ev.a, []string{"unrelated.example.org"}, nil)
		if _, err := ev.svc.Create(ctx, ev.a, ev.external(), request(), ""); err != nil {
			t.Errorf("external with allow list: %v", err)
		}
		// ... unlike an internal sender, bound by the same allow list.
		_, err = ev.svc.Create(ctx, ev.a, internalSender(), request(), "")
		ruleFields(t, err, ErrRecipientDomainRefused)
		events, _, _ = h.audit.snapshot()
		if last := events[len(events)-1]; last.Actor != alice || last.Details["origin"] == originInvitation {
			t.Errorf("last event = %+v", last)
		}
	})
}

func TestCreateExternalInternalOnly(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	levels := strictLevels()
	levels[1].Rules.RequirePassword, levels[1].Rules.ExpiryDaysMask = false, store.ExpiryMaskAll
	ev.setLevels(t, ev.a, levels)
	req := request()
	req.ConfidentialityLevel = "secret"
	// The inviter is internal: the internal-only rule passes.
	d, err := ev.svc.Create(context.Background(), ev.a, ev.external(), req, "")
	if err != nil || d.ConfidentialityLevel != "secret" || !reflect.DeepEqual(d.Recipients, []string{alice}) {
		t.Fatalf("Create = %+v, %v", d, err)
	}
}

func TestCreatePoliciesAPIToken(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		h := ev.withHooks(&auditSpy{writer: audit.New(ev.db)})
		tok := ev.newToken(t, ev.a)
		ev.setLevels(t, ev.a, strictLevels())

		req := tokenRequest()
		req.ConfidentialityLevel = "secret"
		_, err := ev.svc.Create(ctx, ev.a, tokenSender(tok), req, "")
		if got := ruleFields(t, err, ErrConfidentialityRule); len(got) != 3 {
			t.Errorf("token rules = %+v", got)
		}

		ev.setRecipientRules(t, ev.a, nil, []string{"customer.example.net"})
		_, err = ev.svc.Create(ctx, ev.a, tokenSender(tok), tokenRequest(), "")
		ruleFields(t, err, ErrRecipientDomainRefused)
		events, _, _ := h.audit.snapshot()
		last := events[len(events)-1]
		if last.Action != audit.ActionTransferRecipientRefused || last.ActorKind != store.ActorAPIToken ||
			last.Actor != tok || last.Details["origin"] != originAPI {
			t.Errorf("token event = %+v", last)
		}
		for _, ev := range ev.seclog.events {
			if ev.Type != securitylog.RateLimited {
				t.Errorf("security event = %+v", ev)
			}
		}

		req = tokenRequest()
		req.Recipients, req.MaxDownloads = []string{carol}, intp(9)
		d, err := ev.svc.Create(ctx, ev.a, tokenSender(tok), req, "")
		if err != nil || d.ConfidentialityLevel != "open" || *d.MaxDownloads != 9 {
			t.Errorf("token create = %+v, %v", d, err)
		}
	})
}

func TestCreatePolicyIdempotency(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ctx := context.Background()
	req := request()
	d, err := ev.svc.Create(ctx, ev.a, internalSender(), req, "key-1")
	if err != nil {
		t.Fatal(err)
	}
	// The same request is replayed; a different option is a mismatch.
	if again, err := ev.svc.Create(ctx, ev.a, internalSender(), req, "key-1"); err != nil || again.ID != d.ID {
		t.Errorf("replay = %+v, %v", again, err)
	}
	for _, edit := range []func(r *CreateRequest){
		func(r *CreateRequest) { r.MaxDownloads = intp(2) },
		func(r *CreateRequest) { r.ConfidentialityLevel = "public" },
	} {
		changed := request()
		edit(&changed)
		if _, err := ev.svc.Create(ctx, ev.a, internalSender(), changed, "key-1"); !errors.Is(err, ErrIdempotencyMismatch) {
			t.Errorf("changed options = %v", err)
		}
	}
	p, err := ev.svc.validate(req, internalSender(), "")
	if err != nil {
		t.Fatal(err)
	}
	verif := req
	verif.RecipientVerification = true
	if fingerprint(p, req) == fingerprint(p, verif) {
		t.Error("recipient verification not in the fingerprint")
	}
}

func TestCreatePolicyStoreFailures(t *testing.T) {
	ev := newEnv(t, storetest.SQLite(t))
	ev.setLevels(t, ev.a, strictLevels())
	pw := "pw"
	secret := request()
	secret.ConfidentialityLevel, secret.Recipients, secret.ExpiryDays, secret.Password = "secret", []string{carol}, 1, &pw
	for _, c := range []struct {
		method string
		skip   int
		req    CreateRequest
	}{
		{"confidentialityLevels", 0, request()},
		{"recipientRules", 0, request()},
		// The eligibility reads the network rules first.
		{"networkRules", 1, secret},
	} {
		t.Run(c.method, func(t *testing.T) {
			r := ev.faults()
			defer func() { ev.svc.repo = r.inner }()
			r.fail[c.method], r.skip[c.method] = errFault, c.skip
			_, err := ev.svc.Create(context.Background(), ev.a, internalSender(), c.req, "")
			if !errors.Is(err, errFault) {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestRuleError(t *testing.T) {
	err := &RuleError{Kind: ErrRecipientDomainRefused, Fields: []FieldError{{Pointer: "/recipients/0", Code: CodeDomainDenied}}}
	if !errors.Is(err, ErrRecipientDomainRefused) || errors.Is(err, ErrConfidentialityRule) {
		t.Error("Is")
	}
	if got := err.Error(); got != "transfer: recipient domain refused: /recipients/0 (domain-denied)" {
		t.Errorf("Error = %q", got)
	}
}

func TestPolicySnapshot(t *testing.T) {
	var rec store.Transfer
	policy{maxDownloads: intp(2), deleteAfterFirstDownload: true}.snapshot(&rec)
	if rec.ConfidentialityLevel != "" || rec.Rules != nil || rec.ConfidentialityLabel != nil || *rec.MaxDownloads != 2 ||
		!rec.DeleteAfterFirstDownload {
		t.Errorf("without level = %+v", rec)
	}
	level := &strictLevels()[1]
	policy{level: level}.snapshot(&rec)
	if rec.ConfidentialityLevel != "secret" || rec.Rules == nil || rec.MaxDownloads != nil || rec.DeleteAfterFirstDownload {
		t.Fatalf("with level = %+v", rec)
	}
	// The snapshot shares nothing with the level.
	*level.Rules.MaxDownloadsCap, level.Labels["en"] = 9, "changed"
	if *rec.Rules.MaxDownloadsCap != 5 || rec.ConfidentialityLabel["en"] != "Secret EN" {
		t.Errorf("snapshot follows the level: %+v %v", rec.Rules, rec.ConfidentialityLabel)
	}
}
