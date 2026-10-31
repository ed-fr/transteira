package adminauth

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// fakeMailer records the invitation mails. When db is set, it also records
// whether the account of each mail was already committed when it was sent.
type fakeMailer struct {
	db        *store.DB
	mu        sync.Mutex
	mails     []InvitationMail
	committed []bool
	ctxErrs   []error
}

func (m *fakeMailer) SendInvitation(ctx context.Context, im InvitationMail) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mails = append(m.mails, im)
	m.ctxErrs = append(m.ctxErrs, ctx.Err())
	_, err := m.db.Admins().GetByUsername(ctx, im.Username)
	m.committed = append(m.committed, err == nil)
}

func (m *fakeMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.mails)
}

func (m *fakeMailer) last(t *testing.T) InvitationMail {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.mails) == 0 {
		t.Fatal("no invitation mail sent")
	}
	return m.mails[len(m.mails)-1]
}

// withMailer installs a fakeMailer on the service.
func (ev *env) withMailer() *fakeMailer {
	m := &fakeMailer{db: ev.db}
	ev.svc.mailer = m
	return m
}

var mailLinkRe = regexp.MustCompile("^" + regexp.QuoteMeta(baseURL+ActivationPath+"#") + `(act_[A-Za-z0-9]{43})$`)

// mailToken extracts the token of a mailed link.
func mailToken(t *testing.T, im InvitationMail) string {
	t.Helper()
	m := mailLinkRe.FindStringSubmatch(im.Link)
	if m == nil {
		t.Fatalf("malformed mailed link %q", im.Link)
	}
	return m[1]
}

// auditDetails returns the details of the audit events of action, oldest
// first, and fails if the audit log holds one of the secrets.
func (ev *env) auditDetails(t *testing.T, action string, secrets ...string) []string {
	t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{Limit: store.MaxPageSize})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := len(page.Items) - 1; i >= 0; i-- {
		it := page.Items[i]
		for _, s := range secrets {
			if strings.Contains(string(it.Details), s) || strings.Contains(it.ObjectID, s) {
				t.Errorf("audit event %s holds a secret: %s", it.Action, it.Details)
			}
		}
		if it.Action == action {
			out = append(out, string(it.Details))
		}
	}
	return out
}

// mustAdmin reads an account by username.
func (ev *env) mustAdmin(t *testing.T, username string) store.Admin {
	t.Helper()
	a, err := ev.db.Admins().GetByUsername(context.Background(), username)
	if err != nil {
		t.Fatalf("GetByUsername(%s): %v", username, err)
	}
	return a
}

// pending creates a pending delegated admin of tenants tids (copied link).
func (ev *env) pending(t *testing.T, r root, username string, requireTOTP bool, tids ...tenant.ID) (Account, string) {
	t.Helper()
	acc, link, err := ev.svc.Create(context.Background(), r.p, AdminCreate{
		Username: username, Email: username + "@entity-a.example.com", Role: store.RoleDelegatedAdmin,
		TenantIDs: tids, RequireTOTP: &requireTOTP,
	}, ipA)
	if err != nil {
		t.Fatalf("Create(%s): %v", username, err)
	}
	return acc, ev.tokenOf(t, link)
}

func TestCreateInvitation(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)
		base := AdminCreate{Username: "inv.one", Email: "inv.one@entity-b.example.com", Role: store.RoleDelegatedAdmin, TenantIDs: []tenant.ID{ev.b.ID, ev.a.ID}}

		// Validation.
		bad := base
		bad.Invitation = Invitation{Delivery: "pigeon"}
		_, _, err := ev.svc.Create(ctx, r.p, bad, ipA)
		wantInvalid(t, "Create(delivery)", err, "/invitation/delivery")
		bad.Invitation = Invitation{Delivery: store.DeliveryMail, Language: "xx"}
		_, _, err = ev.svc.Create(ctx, r.p, bad, ipA)
		wantInvalid(t, "Create(language)", err, "/invitation/language")

		// Mail without system SMTP: refused, nothing created.
		mailReq := base
		mailReq.Invitation = Invitation{Delivery: store.DeliveryMail}
		_, _, err = ev.svc.Create(ctx, r.p, mailReq, ipA)
		wantErr(t, "Create(mail without mailer)", err, ErrSystemSMTPUnavailable)
		if _, err := ev.db.Admins().GetByUsername(ctx, "inv.one"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("account created despite the refusal: %v", err)
		}

		// Copy (explicit) behaves like the default.
		copyReq := base
		copyReq.Username, copyReq.Email = "inv.copy", "inv.copy@entity-b.example.com"
		copyReq.Invitation = Invitation{Delivery: store.DeliveryCopy}
		_, link, err := ev.svc.Create(ctx, r.p, copyReq, ipA)
		if err != nil || link.Delivery != store.DeliveryCopy {
			t.Fatalf("Create(copy) = %+v, %v", link, err)
		}
		ev.tokenOf(t, link)

		// Mail: TOTP forced, mail sent after the commit, no URL returned.
		mailer := ev.withMailer()
		off := false
		mailReq.RequireTOTP = &off
		acc, link, err := ev.svc.Create(ctx, r.p, mailReq, ipA)
		if err != nil {
			t.Fatalf("Create(mail) = %v", err)
		}
		if !acc.RequireTOTP || link.URL != "" || link.Delivery != store.DeliveryMail ||
			!link.ExpiresAt.Equal(ev.svc.now().Add(ActivationTTL)) {
			t.Errorf("Create(mail) = %+v, %+v", acc, link)
		}
		if !ev.mustAdmin(t, "inv.one").RequireTOTP {
			t.Error("RequireTOTP not forced in the store")
		}
		im := mailer.last(t)
		if mailer.count() != 1 || !mailer.committed[0] || mailer.ctxErrs[0] != nil {
			t.Errorf("mails = %d committed=%v ctx=%v", mailer.count(), mailer.committed, mailer.ctxErrs)
		}
		// The language is the one of the first tenant (B: fr), names sorted.
		wantNames := []string{ev.a.Name, ev.b.Name}
		slices.Sort(wantNames)
		if im.To != "inv.one@entity-b.example.com" || im.Language != "fr" || im.Username != "inv.one" ||
			!slices.Equal(im.TenantNames, wantNames) || !im.ExpiresAt.Equal(link.ExpiresAt) {
			t.Errorf("mail = %+v", im)
		}
		token := mailToken(t, im)
		details := ev.auditDetails(t, "admin.invited", token)
		if len(details) != 2 || !strings.Contains(details[1], `"delivery":"mail"`) || !strings.Contains(details[1], `"language":"fr"`) ||
			!strings.Contains(details[0], `"delivery":"copy"`) || strings.Contains(details[0], "language") {
			t.Errorf("admin.invited details = %v", details)
		}
		if n := ev.countAction(t, "admin.created"); n != 2 {
			t.Errorf("admin.created events = %d, want 2", n)
		}
		if _, err := ev.svc.Activate(ctx, token, newPassword, ipB); err != nil {
			t.Errorf("Activate(mailed token) = %v", err)
		}

		// An explicit language wins over the tenant default.
		en := base
		en.Username, en.Email = "inv.en", "inv.en@entity-b.example.com"
		en.Invitation = Invitation{Delivery: store.DeliveryMail, Language: "en"}
		if _, _, err = ev.svc.Create(ctx, r.p, en, ipA); err != nil {
			t.Fatal(err)
		}
		if got := mailer.last(t).Language; got != "en" {
			t.Errorf("language = %q, want en", got)
		}

		// A failed transaction sends nothing, creates nothing.
		before := mailer.count()
		for _, op := range []string{"tx.createAdmin", "tx.deleteActivations", "tx.createActivation", "tx.audit", "tx.audit.admin.invited", "tenant"} {
			restore := ev.withFaults(op)
			rb := base
			rb.Username, rb.Email = "inv.rollback", "inv.rollback@entity-b.example.com"
			rb.Invitation = Invitation{Delivery: store.DeliveryMail}
			_, _, err = ev.svc.Create(ctx, r.p, rb, ipA)
			restore()
			wantErr(t, "Create(fault "+op+")", err, errFault)
		}
		if mailer.count() != before {
			t.Errorf("a mail was sent for a rolled back creation")
		}
		if _, err := ev.db.Admins().GetByUsername(ctx, "inv.rollback"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("account committed despite the failure: %v", err)
		}
	})
}

func TestInvite(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)
		d := ev.mustDelegated(t, r, "active.one", false, ev.a.ID)

		// Authorization first.
		_, _, err := ev.svc.Invite(ctx, d.p, r.p.Admin.ID, Invitation{}, ipA)
		wantErr(t, "Invite(delegated)", err, ErrForbidden)
		_, _, err = ev.svc.Invite(ctx, Principal{}, r.p.Admin.ID, Invitation{}, ipA)
		wantErr(t, "Invite(anonymous)", err, ErrUnauthenticated)

		acc, oldToken := ev.pending(t, r, "inv.pending", false, ev.b.ID, ev.a.ID)

		// Validation, mail without SMTP, unknown account.
		_, _, err = ev.svc.Invite(ctx, r.p, acc.ID, Invitation{Delivery: "pigeon"}, ipA)
		wantInvalid(t, "Invite(delivery)", err, "/delivery")
		_, _, err = ev.svc.Invite(ctx, r.p, acc.ID, Invitation{Delivery: store.DeliveryMail, Language: "xx"}, ipA)
		wantInvalid(t, "Invite(language)", err, "/language")
		_, _, err = ev.svc.Invite(ctx, r.p, acc.ID, Invitation{Delivery: store.DeliveryMail}, ipA)
		wantErr(t, "Invite(mail without mailer)", err, ErrSystemSMTPUnavailable)
		mailer := ev.withMailer()
		_, _, err = ev.svc.Invite(ctx, r.p, "adm_01UNKNOWN", Invitation{}, ipA)
		wantErr(t, "Invite(unknown)", err, ErrNotFound)

		// Already activated: the credentials must be reset instead.
		_, _, err = ev.svc.Invite(ctx, r.p, d.account.ID, Invitation{}, ipA)
		wantErr(t, "Invite(activated)", err, ErrAdminAlreadyActive)

		// Disabled.
		dis, _ := ev.pending(t, r, "inv.disabled", true, ev.a.ID)
		if _, err := ev.svc.Update(ctx, r.p, dis.ID, AdminUpdate{Disabled: ptr(true)}, ipA); err != nil {
			t.Fatal(err)
		}
		_, _, err = ev.svc.Invite(ctx, r.p, dis.ID, Invitation{}, ipA)
		wantErr(t, "Invite(disabled)", err, ErrAccountDisabled)

		// An activated super admin is refused as any activated account.
		_, _, err = ev.svc.Invite(ctx, r.p, r.p.Admin.ID, Invitation{}, ipA)
		wantErr(t, "Invite(activated super admin)", err, ErrAdminAlreadyActive)
		if mailer.count() != 0 {
			t.Errorf("refused invitations sent %d mails", mailer.count())
		}

		// Copy: the previous link is revoked, the new one returned.
		a2, link, err := ev.svc.Invite(ctx, r.p, acc.ID, Invitation{}, ipA)
		if err != nil || a2.ID != acc.ID || a2.RequireTOTP || link.Delivery != store.DeliveryCopy {
			t.Fatalf("Invite(copy) = %+v, %+v, %v", a2, link, err)
		}
		copyToken := ev.tokenOf(t, link)
		if mailer.count() != 0 {
			t.Error("copy sent a mail")
		}
		_, err = ev.svc.Activate(ctx, oldToken, newPassword, ipB)
		wantErr(t, "Activate(revoked link)", err, ErrNotFound)

		// Mail: TOTP forced on the account, link revoked, mail after commit
		// (language of the first tenant by ID: A, en).
		a3, link, err := ev.svc.Invite(ctx, r.p, acc.ID, Invitation{Delivery: store.DeliveryMail}, ipA)
		if err != nil || !a3.RequireTOTP || link.URL != "" || link.Delivery != store.DeliveryMail {
			t.Fatalf("Invite(mail) = %+v, %+v, %v", a3, link, err)
		}
		if !ev.mustAdmin(t, "inv.pending").RequireTOTP {
			t.Error("RequireTOTP not stored")
		}
		im := mailer.last(t)
		// The account lists its tenants sorted by ID: the first one decides.
		firstLang := map[tenant.ID]string{ev.a.ID: "en", ev.b.ID: "fr"}[a3.TenantIDs[0]]
		if !mailer.committed[0] || im.To != "inv.pending@entity-a.example.com" || im.Language != firstLang || im.Username != "inv.pending" {
			t.Errorf("mail = %+v committed=%v", im, mailer.committed)
		}
		mailed := mailToken(t, im)
		_, err = ev.svc.Activate(ctx, copyToken, newPassword, ipB)
		wantErr(t, "Activate(copy link revoked by the mail)", err, ErrNotFound)

		// Already TOTP-required account: no update needed, language explicit.
		if _, _, err := ev.svc.Invite(ctx, r.p, acc.ID, Invitation{Delivery: store.DeliveryMail, Language: "en"}, ipA); err != nil {
			t.Fatal(err)
		}
		if got := mailer.last(t).Language; got != "en" {
			t.Errorf("language = %q, want en", got)
		}
		details := ev.auditDetails(t, "admin.invited", mailed, copyToken)
		if n := len(details); n < 3 || !strings.Contains(details[n-3], `"delivery":"copy"`) ||
			!strings.Contains(details[n-2], `"language":"`+firstLang+`"`) || !strings.Contains(details[n-1], `"language":"en"`) {
			t.Errorf("admin.invited details = %v", details)
		}

		// Rate limit: 5 per hour per account (3 used above), the 6th fails.
		other, _ := ev.pending(t, r, "inv.other", true, ev.a.ID)
		for i := 0; i < InviteMaxPerHour-3; i++ {
			if _, _, err := ev.svc.Invite(ctx, r.p, acc.ID, Invitation{}, ipA); err != nil {
				t.Fatalf("Invite #%d = %v", i+4, err)
			}
		}
		_, _, err = ev.svc.Invite(ctx, r.p, acc.ID, Invitation{}, ipA)
		rl := wantLimited(t, "Invite(6th)", err)
		if rl.RetryAfter <= 0 || rl.RetryAfter > InviteWindow {
			t.Errorf("RetryAfter = %v", rl.RetryAfter)
		}
		if _, _, err := ev.svc.Invite(ctx, r.p, other.ID, Invitation{}, ipA); err != nil {
			t.Errorf("Invite(other account) = %v", err)
		}
		ev.clock.Advance(InviteWindow + time.Second)
		if _, _, err := ev.svc.Invite(ctx, r.p, acc.ID, Invitation{}, ipA); err != nil {
			t.Errorf("Invite(after the window) = %v", err)
		}
	})
}

// TestInviteSuperAdminCopy checks that a pending super admin account can be
// re-invited with a copied link and the default language.
func TestInviteSuperAdminCopy(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)
		mailer := ev.withMailer()
		super, _ := ev.mustSuper(t, r, "second.super")
		// A credentials reset leaves a pending super admin account.
		if _, _, err := ev.svc.ResetCredentials(ctx, r.p, super.ID, ipA); err != nil {
			t.Fatalf("ResetCredentials: %v", err)
		}
		acc := super
		_, link, err := ev.svc.Invite(ctx, r.p, acc.ID, Invitation{}, ipA)
		if err != nil || link.Delivery != store.DeliveryCopy {
			t.Fatalf("Invite(super admin, copy) = %+v, %v", link, err)
		}
		ev.tokenOf(t, link)
		_, _, err = ev.svc.Invite(ctx, r.p, acc.ID, Invitation{Delivery: store.DeliveryMail}, ipA)
		var na *NotAllowedError
		if !errors.As(err, &na) || na.Field != "/delivery" || !errors.Is(err, ErrInvalid) || na.Error() == "" {
			t.Errorf("Invite(super admin, mail) = %v", err)
		}
		if mailer.count() != 0 {
			t.Error("a mail was sent to a super admin")
		}
	})
}

func TestInviteFaults(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)
		mailer := ev.withMailer()
		acc, token := ev.pending(t, r, "inv.fault", false, ev.a.ID)
		for _, op := range []string{"admin", "tenant", "tx.admin", "tx.updateAdmin", "tx.deleteActivations", "tx.createActivation", "tx.audit", "tx.audit.admin.invited"} {
			restore := ev.withFaults(op)
			_, _, err := ev.svc.Invite(ctx, r.p, acc.ID, Invitation{Delivery: store.DeliveryMail}, ipA)
			restore()
			wantErr(t, "Invite(fault "+op+")", err, errFault)
		}
		// The account vanished between the first read and the transaction.
		restore := ev.withRepo(func(r repo) faultRepo {
			return faultRepo{repo: r, fails: map[string]error{"tx.admin": store.ErrNotFound}}
		})
		_, _, err := ev.svc.Invite(ctx, r.p, acc.ID, Invitation{}, ipA)
		restore()
		wantErr(t, "Invite(vanished)", err, ErrNotFound)
		if mailer.count() != 0 {
			t.Errorf("rolled back invitations sent %d mails", mailer.count())
		}
		// Everything rolled back: TOTP not forced, old link still valid.
		if ev.mustAdmin(t, "inv.fault").RequireTOTP {
			t.Error("RequireTOTP committed despite the rollback")
		}
		if _, err := ev.svc.Activate(ctx, token, newPassword, ipB); err != nil {
			t.Errorf("Activate(old link) = %v", err)
		}
	})
}

// delegatedTenant is a new tenant created with its delegated admin.
func (ev *env) createTenantWith(t *testing.T, p Principal, fqdn string, in DelegatedAdmin) (*tenant.Tenant, Account, Activation, error) {
	t.Helper()
	var (
		acc  Account
		link Activation
	)
	tn, err := ev.db.Tenants().CreateWith(context.Background(), &tenant.Tenant{
		Name: "New " + fqdn, FQDN: fqdn, DefaultLanguage: "en", MaxTransferBytes: 1 << 30, StorageQuotaBytes: 100 << 30,
	}, func(tx *store.SystemTx, created *tenant.Tenant) error {
		var err error
		acc, link, err = ev.svc.CreateDelegatedAdminTx(context.Background(), tx, p, created, in, ipA)
		return err
	})
	return tn, acc, link, err
}

func TestCreateDelegatedAdminTx(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)
		d := ev.mustDelegated(t, r, "active.two", false, ev.a.ID)
		good := DelegatedAdmin{Username: "First.Admin", Email: "first@entity-d.example.com", Language: "fr"}

		tenantGone := func(fqdn string) {
			t.Helper()
			if _, err := ev.db.Tenants().TenantByFQDN(ctx, fqdn); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("tenant %s exists after a failure: %v", fqdn, err)
			}
		}

		// Authorization.
		_, _, _, err := ev.createTenantWith(t, d.p, "d1.example.com", good)
		wantErr(t, "forbidden", err, ErrForbidden)
		_, _, _, err = ev.createTenantWith(t, Principal{}, "d1.example.com", good)
		wantErr(t, "unauthenticated", err, ErrUnauthenticated)
		tenantGone("d1.example.com")

		// Validation.
		for name, tc := range map[string]struct {
			mut   func(*DelegatedAdmin)
			field string
		}{
			"username": {func(a *DelegatedAdmin) { a.Username = "a b" }, FieldUsername},
			"email":    {func(a *DelegatedAdmin) { a.Email = "nope" }, FieldEmail},
			"language": {func(a *DelegatedAdmin) { a.Language = "" }, FieldLanguage},
			"unknown":  {func(a *DelegatedAdmin) { a.Language = "xx" }, FieldLanguage},
			"delivery": {func(a *DelegatedAdmin) { a.Delivery = "pigeon" }, FieldDelivery},
		} {
			in := good
			tc.mut(&in)
			_, _, _, err := ev.createTenantWith(t, r.p, "d2.example.com", in)
			wantInvalid(t, name, err, tc.field)
		}
		tenantGone("d2.example.com")

		// Mail without SMTP.
		in := good
		in.Delivery = store.DeliveryMail
		_, _, _, err = ev.createTenantWith(t, r.p, "d3.example.com", in)
		wantErr(t, "mail without mailer", err, ErrSystemSMTPUnavailable)
		tenantGone("d3.example.com")

		// Copy.
		tn, acc, link, err := ev.createTenantWith(t, r.p, "d4.example.com", good)
		if err != nil {
			t.Fatalf("copy = %v", err)
		}
		ev.tokenOf(t, link)
		if acc.Username != "first.admin" || acc.Role != store.RoleDelegatedAdmin || !acc.RequireTOTP || acc.Language != "fr" ||
			!slices.Equal(acc.TenantIDs, []tenant.ID{tn.ID}) || link.Delivery != store.DeliveryCopy {
			t.Errorf("account = %+v link = %+v", acc, link)
		}
		if got := ev.countAction(t, "admin.created"); got != 2 {
			t.Errorf("admin.created = %d", got)
		}

		// Username conflict: the tenant is not created.
		dup := good
		dup.Email = "other@entity-d.example.com"
		_, _, _, err = ev.createTenantWith(t, r.p, "d5.example.com", dup)
		wantErr(t, "conflict", err, ErrAlreadyExists)
		tenantGone("d5.example.com")

		// Mail: queued after the commit only, rolled back with the tenant.
		mailer := ev.withMailer()
		mail := DelegatedAdmin{Username: "mailed.admin", Email: "mailed@entity-d.example.com", Language: "en", Delivery: store.DeliveryMail}
		tn, acc, link, err = ev.createTenantWith(t, r.p, "d6.example.com", mail)
		if err != nil {
			t.Fatalf("mail = %v", err)
		}
		im := mailer.last(t)
		if link.URL != "" || link.Delivery != store.DeliveryMail || mailer.count() != 1 || !mailer.committed[0] ||
			im.To != "mailed@entity-d.example.com" || im.Language != "en" || im.Username != "mailed.admin" ||
			!slices.Equal(im.TenantNames, []string{tn.Name}) {
			t.Errorf("mail = %+v link = %+v", im, link)
		}
		token := mailToken(t, im)
		if _, err := ev.svc.Activate(ctx, token, newPassword, ipB); err != nil {
			t.Errorf("Activate = %v", err)
		}
		details := ev.auditDetails(t, "admin.invited", token)
		if n := len(details); n < 1 || !strings.Contains(details[n-1], `"language":"en"`) {
			t.Errorf("admin.invited = %v", details)
		}

		// A later failure of the caller rolls everything back, no mail.
		errLater := errors.New("later failure")
		_, err = ev.db.Tenants().CreateWith(ctx, &tenant.Tenant{
			Name: "Later", FQDN: "d7.example.com", DefaultLanguage: "en", MaxTransferBytes: 1 << 30, StorageQuotaBytes: 100 << 30,
		}, func(tx *store.SystemTx, created *tenant.Tenant) error {
			in := DelegatedAdmin{Username: "later.admin", Email: "later@entity-d.example.com", Language: "en", Delivery: store.DeliveryMail}
			if _, _, err := ev.svc.CreateDelegatedAdminTx(ctx, tx, r.p, created, in, ipA); err != nil {
				return err
			}
			return errLater
		})
		wantErr(t, "later failure", err, errLater)
		tenantGone("d7.example.com")
		if mailer.count() != 1 {
			t.Errorf("mails = %d after a rollback, want 1", mailer.count())
		}
		if _, err := ev.db.Admins().GetByUsername(ctx, "later.admin"); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("account committed despite the rollback: %v", err)
		}

		// Fault injection on each step.
		for _, op := range []string{"tx.createAdmin", "tx.deleteActivations", "tx.createActivation", "tx.audit"} {
			restore := ev.withFaults(op)
			_, _, _, err := ev.createTenantWith(t, r.p, "d8.example.com", DelegatedAdmin{
				Username: "fault.admin", Email: "fault@entity-d.example.com", Language: "en", Delivery: store.DeliveryMail,
			})
			restore()
			wantErr(t, "fault "+op, err, errFault)
		}
		tenantGone("d8.example.com")
		if mailer.count() != 1 {
			t.Errorf("mails = %d after faults, want 1", mailer.count())
		}
	})
}

func TestMailLanguage(t *testing.T) {
	for name, tc := range map[string]struct {
		inv     Invitation
		tenants []tenantInfo
		want    string
	}{
		"explicit":        {Invitation{Language: "fr"}, []tenantInfo{{"A", "en"}}, "fr"},
		"first tenant":    {Invitation{}, []tenantInfo{{"A", "fr"}, {"B", "en"}}, "fr"},
		"no tenant":       {Invitation{}, nil, "en"},
		"unsupported one": {Invitation{}, []tenantInfo{{"A", "xx"}}, "en"},
	} {
		if got := mailLanguage(tc.inv, tc.tenants); got != tc.want {
			t.Errorf("%s: mailLanguage = %q, want %q", name, got, tc.want)
		}
	}
}

// TestActivateMailedLinkForcesTOTP checks that a mailed link ends with a TOTP
// enrollment even when the super admin lifted the requirement after the
// invitation (T-254), that a copied link keeps the account's setting, and
// that the forced requirement is rolled back with the activation.
func TestActivateMailedLinkForcesTOTP(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)
		mailer := ev.withMailer()
		lift := func(id string) {
			t.Helper()
			if _, err := ev.svc.Update(ctx, r.p, id, AdminUpdate{RequireTOTP: ptr(false)}, ipA); err != nil {
				t.Fatalf("Update: %v", err)
			}
		}
		invite := func(username string, delivery store.ActivationDelivery) (Account, string) {
			t.Helper()
			acc, link, err := ev.svc.Create(ctx, r.p, AdminCreate{
				Username: username, Email: username + "@entity-a.example.com", Role: store.RoleDelegatedAdmin,
				TenantIDs: []tenant.ID{ev.a.ID}, Invitation: Invitation{Delivery: delivery},
			}, ipA)
			if err != nil {
				t.Fatal(err)
			}
			if delivery == store.DeliveryMail {
				return acc, mailToken(t, mailer.last(t))
			}
			return acc, ev.tokenOf(t, link)
		}

		// Mailed, then lifted: the activation imposes the enrollment again.
		acc, token := invite("forced.mail", store.DeliveryMail)
		lift(acc.ID)
		if ev.mustAdmin(t, "forced.mail").RequireTOTP {
			t.Fatal("the requirement was not lifted")
		}
		sess, err := ev.svc.Activate(ctx, token, newPassword, ipB)
		if err != nil || sess.State != store.SessionTOTPEnrollmentRequired {
			t.Fatalf("Activate(mailed) = %+v, %v", sess, err)
		}
		if !ev.mustAdmin(t, "forced.mail").RequireTOTP {
			t.Error("RequireTOTP not restored")
		}

		// Mailed and still required: same state, no extra update needed.
		acc, token = invite("kept.mail", store.DeliveryMail)
		if sess, err = ev.svc.Activate(ctx, token, newPassword, ipB); err != nil || sess.State != store.SessionTOTPEnrollmentRequired {
			t.Fatalf("Activate(mailed, required) = %+v, %v", sess, err)
		}

		// Copied and lifted: the account keeps its setting.
		acc, token = invite("lifted.copy", store.DeliveryCopy)
		lift(acc.ID)
		if sess, err = ev.svc.Activate(ctx, token, newPassword, ipB); err != nil || sess.State != store.SessionAuthenticated {
			t.Fatalf("Activate(copy, lifted) = %+v, %v", sess, err)
		}
		if ev.mustAdmin(t, "lifted.copy").RequireTOTP {
			t.Error("a copied link imposed TOTP")
		}

		// A failure of the update rolls the activation back.
		acc, token = invite("fault.mail", store.DeliveryMail)
		lift(acc.ID)
		restore := ev.withFaults("tx.updateAdmin")
		_, err = ev.svc.Activate(ctx, token, newPassword, ipB)
		restore()
		wantErr(t, "Activate(fault)", err, errFault)
		if got := ev.mustAdmin(t, "fault.mail"); got.PasswordHash != "" {
			t.Error("the password was set despite the failure")
		}
		if _, err := ev.svc.Activate(ctx, token, newPassword, ipB); err != nil {
			t.Errorf("the link was consumed by the failed activation: %v", err)
		}
	})
}

// TestInviteRecordsForcedTOTP checks the require_totp_forced detail of the
// admin.invited event: present only when the invitation switched TOTP on.
func TestInviteRecordsForcedTOTP(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		r := ev.mustSetup(t)
		ev.withMailer()
		off, _ := ev.pending(t, r, "forced.off", false, ev.a.ID)
		on, _ := ev.pending(t, r, "forced.on", true, ev.a.ID)
		last := func() string {
			d := ev.auditDetails(t, "admin.invited")
			return d[len(d)-1]
		}
		if _, _, err := ev.svc.Invite(ctx, r.p, off.ID, Invitation{}, ipA); err != nil || strings.Contains(last(), "require_totp_forced") {
			t.Errorf("copy: %v %s", err, last())
		}
		if _, _, err := ev.svc.Invite(ctx, r.p, on.ID, Invitation{Delivery: store.DeliveryMail}, ipA); err != nil || strings.Contains(last(), "require_totp_forced") {
			t.Errorf("mail, already required: %v %s", err, last())
		}
		if _, _, err := ev.svc.Invite(ctx, r.p, off.ID, Invitation{Delivery: store.DeliveryMail}, ipA); err != nil || !strings.Contains(last(), `"require_totp_forced":true`) {
			t.Errorf("mail, forced: %v %s", err, last())
		}
	})
}
