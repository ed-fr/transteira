package tenantadmin

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"slices"
	"sync"
	"testing"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// nopHasher is a PasswordHasher for the tests that never log in.
type nopHasher struct{}

func (nopHasher) HashPassword(context.Context, []byte) (string, error) { return "$fake$00", nil }
func (nopHasher) VerifyPassword(context.Context, string, []byte) (bool, error) {
	return false, nil
}

// inviteMailer records the invitation mails and whether the tenant of each
// was committed when it was sent.
type inviteMailer struct {
	db        *store.DB
	mu        sync.Mutex
	mails     []adminauth.InvitationMail
	committed []bool
}

func (m *inviteMailer) SendInvitation(ctx context.Context, im adminauth.InvitationMail) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mails = append(m.mails, im)
	_, err := m.db.Admins().GetByUsername(ctx, im.Username)
	m.committed = append(m.committed, err == nil)
}

// withAdmins plugs a real adminauth service (and, when mail is true, a
// recording invitation mailer) into the service of ev.
func (ev *env) withAdmins(t *testing.T, mail bool) *inviteMailer {
	t.Helper()
	kr, err := masterkey.New(masterkeytest.Key(t, "tenantadmin-admins"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(kr.Close)
	m := &inviteMailer{db: ev.db}
	opts := adminauth.Options{AdminBaseURL: "https://" + adminHost, Now: ev.clock.Now}
	if mail {
		opts.Mailer = m
	}
	admins, err := adminauth.New(ev.db, kr, ev.vault, nopHasher{}, securitylog.New(io.Discard), opts)
	if err != nil {
		t.Fatal(err)
	}
	ev.svc.admins = admins
	return m
}

// tenantGone fails if the tenant with fqdn exists.
func (ev *env) tenantGone(t *testing.T, fqdn string) {
	t.Helper()
	if _, err := ev.db.Tenants().TenantByFQDN(context.Background(), fqdn); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("tenant %s exists after a failure: %v", fqdn, err)
	}
}

func TestCreateTenantDelegatedAdmin(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		in := func(fqdn string, da *adminauth.DelegatedAdmin) TenantCreate {
			return TenantCreate{SetupState: tenant.SetupStateActive, Name: "New", FQDN: fqdn, DefaultLanguage: "fr", StorageQuotaBytes: 1 << 40, DelegatedAdmin: da}
		}
		good := adminauth.DelegatedAdmin{Username: "first.admin", Email: "first@entity-c.example.com", Language: "fr"}

		// Without an admin creator, the request is refused as a whole.
		_, err := ev.svc.CreateTenant(ctx, ev.super, in("c0.example.com", &good), clientIP)
		if err == nil {
			t.Fatal("CreateTenant with a delegated admin and no creator succeeded")
		}
		ev.tenantGone(t, "c0.example.com")

		// No delegated admin: no creator needed.
		v, err := ev.svc.CreateTenant(ctx, ev.super, in("c00.example.com", nil), clientIP)
		mustNoErr(t, "no admin", err)
		if v.DelegatedAdmin != nil {
			t.Errorf("DelegatedAdmin = %+v", v.DelegatedAdmin)
		}

		ev.withAdmins(t, false)

		// Mail without a system SMTP.
		mail := good
		mail.Delivery = store.DeliveryMail
		_, err = ev.svc.CreateTenant(ctx, ev.super, in("c1.example.com", &mail), clientIP)
		wantErr(t, "mail without smtp", err, adminauth.ErrSystemSMTPUnavailable)
		ev.tenantGone(t, "c1.example.com")

		// Invalid field: nothing is created.
		bad := good
		bad.Language = "xx"
		_, err = ev.svc.CreateTenant(ctx, ev.super, in("c2.example.com", &bad), clientIP)
		var ie *adminauth.InvalidError
		if !errors.As(err, &ie) || ie.Field != adminauth.FieldLanguage {
			t.Errorf("invalid language: err = %v", err)
		}
		ev.tenantGone(t, "c2.example.com")

		// Copy.
		got, err := ev.svc.CreateTenant(ctx, ev.super, in("c3.example.com", &good), clientIP)
		mustNoErr(t, "copy", err)
		da := got.DelegatedAdmin
		if da == nil || da.Activation.URL == "" || da.Activation.Delivery != store.DeliveryCopy ||
			da.Account.Username != "first.admin" || !da.Account.RequireTOTP ||
			!slices.Equal(da.Account.TenantIDs, []tenant.ID{got.ID}) {
			t.Fatalf("DelegatedAdmin = %+v", da)
		}
		if n := len(ev.auditEvents(t, got.ID, ActionTenantCreated)); n != 1 {
			t.Errorf("tenant.created events = %d", n)
		}

		// Username conflict: the whole creation is refused.
		dup := good
		dup.Email = "dup@entity-c.example.com"
		_, err = ev.svc.CreateTenant(ctx, ev.super, in("c4.example.com", &dup), clientIP)
		wantErr(t, "username conflict", err, ErrAlreadyExists)
		ev.tenantGone(t, "c4.example.com")

		// A mail-delivered admin, with the system SMTP: queued after the
		// commit, the link is not returned.
		mailer := ev.withAdmins(t, true)
		mail.Username, mail.Email = "mailed.admin", "mailed@entity-c.example.com"
		got, err = ev.svc.CreateTenant(ctx, ev.super, in("c5.example.com", &mail), clientIP)
		mustNoErr(t, "mail", err)
		if got.DelegatedAdmin == nil || got.DelegatedAdmin.Activation.URL != "" ||
			got.DelegatedAdmin.Activation.Delivery != store.DeliveryMail {
			t.Fatalf("DelegatedAdmin = %+v", got.DelegatedAdmin)
		}
		if len(mailer.mails) != 1 || !mailer.committed[0] || mailer.mails[0].To != "mailed@entity-c.example.com" ||
			!slices.Equal(mailer.mails[0].TenantNames, []string{"New"}) {
			t.Errorf("mails = %+v committed=%v", mailer.mails, mailer.committed)
		}

		// A failure after the admin was created: rolled back, no mail.
		ev.faults("createTenant")
		mail.Username, mail.Email = "ghost.admin", "ghost@entity-c.example.com"
		_, err = ev.svc.CreateTenant(ctx, ev.super, in("c6.example.com", &mail), clientIP)
		wantErr(t, "createTenant fault", err, errBoom)
		ev.tenantGone(t, "c6.example.com")
		if len(mailer.mails) != 1 {
			t.Errorf("a mail was queued for a failed creation: %d", len(mailer.mails))
		}
	})
}

// fakeAdminCreator returns err (and creates nothing).
type fakeAdminCreator struct{ err error }

func (f fakeAdminCreator) CreateDelegatedAdminTx(context.Context, *store.SystemTx, adminauth.Principal, *tenant.Tenant,
	adminauth.DelegatedAdmin, netip.Addr,
) (adminauth.Account, adminauth.Activation, error) {
	return adminauth.Account{}, adminauth.Activation{}, f.err
}

func (f fakeAdminCreator) CreateProvisionedAdminTx(context.Context, *store.SystemTx, adminauth.AuditActor, *tenant.Tenant,
	adminauth.DelegatedAdmin, netip.Addr,
) (adminauth.Account, adminauth.Activation, error) {
	return adminauth.Account{}, adminauth.Activation{}, f.err
}

func TestCreateTenantDelegatedAdminErrors(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		da := &adminauth.DelegatedAdmin{Username: "x.admin", Email: "x@entity-c.example.com", Language: "en"}
		for name, tc := range map[string]struct {
			err  error
			want error
		}{
			"forbidden":       {adminauth.ErrForbidden, adminauth.ErrForbidden},
			"unauthenticated": {adminauth.ErrUnauthenticated, adminauth.ErrUnauthenticated},
			"already exists":  {adminauth.ErrAlreadyExists, ErrAlreadyExists},
			"unexpected":      {errBoom, errBoom},
		} {
			ev.svc.admins = fakeAdminCreator{err: tc.err}
			_, err := ev.svc.CreateTenant(ctx, ev.super, TenantCreate{
				SetupState: tenant.SetupStateActive,
				Name:       "New", FQDN: "e1.example.com", DefaultLanguage: "en", StorageQuotaBytes: 1, DelegatedAdmin: da,
			}, clientIP)
			wantErr(t, name, err, tc.want)
			ev.tenantGone(t, "e1.example.com")
		}
	})
}

// TestCreateTenantViewFailure checks the error when the created tenant
// cannot be read back (the tenant stays created).
func TestCreateTenantViewFailure(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ev.faults("usedBytes")
		_, err := ev.svc.CreateTenant(context.Background(), ev.super, TenantCreate{
			SetupState: tenant.SetupStateActive,
			Name:       "New", FQDN: "v1.example.com", DefaultLanguage: "en", StorageQuotaBytes: 1,
		}, clientIP)
		wantErr(t, "view", err, errBoom)
	})
}
