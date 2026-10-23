package maintenance_test

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/maintenance"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

var (
	storeNow  = time.Date(2026, 10, 22, 18, 0, 0, 0, time.UTC)
	procStart = time.Date(2026, 10, 22, 7, 30, 0, 0, time.UTC)
	clientIP  = netip.MustParseAddr("192.0.2.10")
)

// openDB returns a migrated database on engine e whose clock is storeNow.
func openDB(t *testing.T, e storetest.Engine) *store.DB {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, e.Config(), store.WithClock(func() time.Time { return storeNow }))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db
}

// principal returns an authenticated session of an administrator.
func principal(role store.AdminRole) adminauth.Principal {
	return adminauth.Principal{
		SessionID: "as_01", State: store.SessionAuthenticated,
		Admin: adminauth.Account{ID: "adm_01", Username: "root", Role: role},
	}
}

var (
	superAdmin = principal(store.RoleSuperAdmin)
	delegated  = principal(store.RoleDelegatedAdmin)
)

func newMode(t *testing.T, db *store.DB, opts maintenance.Options) *maintenance.Mode {
	t.Helper()
	m, err := maintenance.New(context.Background(), db.SystemSettings(), audit.New(db), opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// TestAdminLifecycle enables and disables the mode as the super admin on
// both engines: state, persistence across a restart, audit in the same
// transaction.
func TestAdminLifecycle(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		m := newMode(t, db, maintenance.Options{})
		if m.Active() {
			t.Fatal("active on a new database")
		}
		st, err := m.Get(ctx, delegated)
		if err != nil || st.Enabled || st.Source != maintenance.SourceNone || st.AdminEnabled || !st.Since.IsZero() ||
			st.Message == nil || len(st.Message) != 0 {
			t.Fatalf("initial state %+v, %v", st, err)
		}
		if m.Message("fr", "fr") != "" {
			t.Error("message while off")
		}

		msgs := map[string]string{"fr": "Retour vers 20 h.", "en": "Back around 8 pm.\nSorry."}
		st, err = m.Set(ctx, superAdmin, true, msgs, clientIP)
		if err != nil {
			t.Fatalf("Set on: %v", err)
		}
		if !st.Enabled || st.Source != maintenance.SourceAdmin || !st.AdminEnabled || !st.Since.Equal(storeNow) ||
			!maps.Equal(st.Message, msgs) || !m.Active() {
			t.Fatalf("state after Set on %+v", st)
		}
		msgs["fr"] = "changed by the caller"
		if m.Message("fr", "en") != "Retour vers 20 h." {
			t.Error("the caller's map is shared with the mode")
		}
		st.Message["en"] = "changed through the state"
		if m.Message("en", "en") != "Back around 8 pm.\nSorry." {
			t.Error("the state map is shared with the mode")
		}

		// Persisted: a restart (not forced) reloads the choice.
		again := newMode(t, db, maintenance.Options{})
		if st := again.State(); !st.Enabled || st.Source != maintenance.SourceAdmin || !st.Since.Equal(storeNow) ||
			st.Message["fr"] != "Retour vers 20 h." {
			t.Fatalf("reloaded state %+v", st)
		}

		// Enabled again: the start is kept, the messages replaced.
		st, err = m.Set(ctx, superAdmin, true, nil, clientIP)
		if err != nil || !st.Since.Equal(storeNow) || len(st.Message) != 0 || m.Message("en", "fr") != "" {
			t.Fatalf("Set on again: %+v, %v", st, err)
		}

		st, err = m.Set(ctx, superAdmin, false, map[string]string{"en": "kept for next time"}, clientIP)
		if err != nil || st.Enabled || st.Source != maintenance.SourceNone || st.AdminEnabled || !st.Since.IsZero() ||
			st.Message["en"] != "kept for next time" || m.Active() || m.Message("en", "en") != "" {
			t.Fatalf("Set off: %+v, %v", st, err)
		}

		page, err := db.AuditEvents().List(ctx, store.AuditFilter{})
		if err != nil || len(page.Items) != 3 {
			t.Fatalf("audit events %d, %v", len(page.Items), err)
		}
		want := map[string]string{
			string(audit.ActionMaintenanceEnabled):  "",
			string(audit.ActionMaintenanceDisabled): `{"languages":["en"]}`,
		}
		var withLanguages bool
		for _, ev := range page.Items {
			if ev.TenantID != "" || ev.ActorKind != store.ActorAdmin || ev.Actor != "root" || ev.IP != clientIP ||
				ev.ObjectKind != audit.ObjectSystem || ev.ObjectID != maintenance.ObjectID {
				t.Errorf("event %+v", ev)
			}
			details := strings.ReplaceAll(string(ev.Details), " ", "")
			if details == `{"languages":["en","fr"]}` {
				withLanguages = true
				continue
			}
			if exp, ok := want[ev.Action]; !ok || (details != exp && (exp != "" || (details != "" && details != "null"))) {
				t.Errorf("event %s details %q", ev.Action, details)
			}
		}
		if !withLanguages {
			t.Error("no event lists the languages of the messages")
		}
	})
}

// TestForcedByEnvironment checks TT_MAINTENANCE: it wins over the stored
// choice, dates the maintenance at the process start, refuses a disable
// and accepts an enable, which stores the message.
func TestForcedByEnvironment(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		m := newMode(t, db, maintenance.Options{Forced: true, Start: procStart})
		st := m.State()
		if !m.Active() || !st.Enabled || st.Source != maintenance.SourceEnvironment || st.AdminEnabled || !st.Since.Equal(procStart) {
			t.Fatalf("forced state %+v", st)
		}
		if _, err := m.Set(ctx, superAdmin, false, nil, clientIP); !errors.Is(err, maintenance.ErrForcedByEnvironment) {
			t.Fatalf("disable while forced: %v", err)
		}
		st, err := m.Set(ctx, superAdmin, true, map[string]string{"en": "Upgrade."}, clientIP)
		if err != nil || st.Source != maintenance.SourceEnvironment || !st.AdminEnabled || !st.Since.Equal(procStart) ||
			m.Message("fr", "fr") != "Upgrade." {
			t.Fatalf("enable while forced: %+v, %v", st, err)
		}
		// Lifting the override leaves the stored choice in effect.
		m.Force(false)
		if st := m.State(); !st.Enabled || st.Source != maintenance.SourceAdmin || !st.Since.Equal(storeNow) {
			t.Fatalf("after the override %+v", st)
		}
		if _, err := m.Set(ctx, superAdmin, false, nil, clientIP); err != nil || m.Active() {
			t.Fatalf("disable after the override: %v", err)
		}
	})
}

// TestForce checks the run-time override and its start.
func TestForce(t *testing.T) {
	now := procStart
	repo := &fakeRepo{}
	m, err := maintenance.New(context.Background(), repo, &fakeAuditor{}, maintenance.Options{
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	m.Force(true)
	now = now.Add(time.Hour)
	m.Force(true) // already forced: the start is kept
	if st := m.State(); !st.Enabled || st.Source != maintenance.SourceEnvironment || !st.Since.Equal(procStart) {
		t.Fatalf("forced %+v", st)
	}
	m.Force(false)
	if st := m.State(); st.Enabled || !st.Since.IsZero() || m.Active() {
		t.Fatalf("after Force(false) %+v", st)
	}

	// Forced from the start without a start time: the clock.
	m, err = maintenance.New(context.Background(), repo, &fakeAuditor{}, maintenance.Options{
		Forced: true, Now: func() time.Time { return now },
	})
	if err != nil || !m.State().Since.Equal(now) {
		t.Fatalf("forced without start: %v", err)
	}
	// The default clock.
	before := time.Now()
	m, err = maintenance.New(context.Background(), repo, &fakeAuditor{}, maintenance.Options{Forced: true})
	if err != nil || m.State().Since.Before(before) {
		t.Fatalf("default clock: %v", err)
	}
}

// TestMessageFallback checks the order: negotiated language, tenant
// default, English, then any supported language, then any key.
func TestMessageFallback(t *testing.T) {
	tests := []struct {
		name          string
		messages      map[string]string
		lang, deflt   string
		want          string
		wantNoMessage bool
	}{
		{"negotiated", map[string]string{"fr": "FR", "en": "EN"}, "fr", "en", "FR", false},
		{"tenant default", map[string]string{"fr": "FR", "en": "EN"}, "de", "fr", "FR", false},
		{"english", map[string]string{"fr": "FR", "en": "EN"}, "de", "it", "EN", false},
		{"any supported", map[string]string{"fr": "FR"}, "en", "en", "FR", false},
		{"any key", map[string]string{"zz": "ZZ", "yy": "YY"}, "en", "fr", "YY", false},
		{"none", map[string]string{}, "en", "fr", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &fakeRepo{row: store.SystemSettingsRow{MaintenanceEnabled: true, MaintenanceMessage: tt.messages}}
			m, err := maintenance.New(context.Background(), repo, &fakeAuditor{}, maintenance.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if got := m.Message(tt.lang, tt.deflt); got != tt.want {
				t.Errorf("Message(%q, %q) = %q, want %q", tt.lang, tt.deflt, got, tt.want)
			}
		})
	}
	// A nil map from the repository is an empty one.
	m, err := maintenance.New(context.Background(), &fakeRepo{}, &fakeAuditor{}, maintenance.Options{})
	if err != nil || m.State().Message == nil {
		t.Fatalf("nil messages: %v", err)
	}
}

// TestMessageNoAlloc checks that the usual lookups (negotiated language,
// tenant default, English) do not allocate: Message runs on every request
// during a maintenance.
func TestMessageNoAlloc(t *testing.T) {
	repo := &fakeRepo{row: store.SystemSettingsRow{MaintenanceEnabled: true, MaintenanceMessage: map[string]string{"fr": "FR", "en": "EN"}}}
	m, err := maintenance.New(context.Background(), repo, &fakeAuditor{}, maintenance.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{"fr", "en"}, {"de", "fr"}, {"de", "it"}} {
		if n := testing.AllocsPerRun(100, func() { _ = m.Message(c[0], c[1]) }); n != 0 {
			t.Errorf("Message(%q, %q) allocates %v times, want 0", c[0], c[1], n)
		}
	}
}

// TestAuthorization checks the roles and sessions of Get and Set.
func TestAuthorization(t *testing.T) {
	ctx := context.Background()
	repo := &fakeRepo{}
	m, err := maintenance.New(ctx, repo, &fakeAuditor{}, maintenance.Options{})
	if err != nil {
		t.Fatal(err)
	}
	pending := superAdmin
	pending.State = store.SessionTOTPRequired
	disabled := superAdmin
	disabled.Admin.Disabled = true
	for name, tt := range map[string]struct {
		p        adminauth.Principal
		get, set error
	}{
		"none":      {adminauth.Principal{}, adminauth.ErrUnauthenticated, adminauth.ErrUnauthenticated},
		"pending":   {pending, adminauth.ErrUnauthenticated, adminauth.ErrUnauthenticated},
		"delegated": {delegated, nil, adminauth.ErrForbidden},
		"disabled":  {disabled, nil, adminauth.ErrForbidden},
		"super":     {superAdmin, nil, nil},
	} {
		if _, err := m.Get(ctx, tt.p); !errors.Is(err, tt.get) {
			t.Errorf("%s: Get = %v, want %v", name, err, tt.get)
		}
		if _, err := m.Set(ctx, tt.p, true, nil, clientIP); !errors.Is(err, tt.set) {
			t.Errorf("%s: Set = %v, want %v", name, err, tt.set)
		}
	}
}

// TestValidation checks the messages refused with the JSON pointer of the
// member, before anything is stored.
func TestValidation(t *testing.T) {
	ctx := context.Background()
	repo := &fakeRepo{}
	m, err := maintenance.New(ctx, repo, &fakeAuditor{}, maintenance.Options{})
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("é", maintenance.MaxMessageRunes)
	tests := []struct {
		name     string
		messages map[string]string
		field    string
	}{
		{"unsupported language", map[string]string{"de": "Hallo"}, "/message/de"},
		{"region tag", map[string]string{"fr-CH": "Salut"}, "/message/fr-CH"},
		{"escaped key", map[string]string{"a/b~c": "x"}, "/message/a~1b~0c"},
		{"empty key", map[string]string{"": "x"}, "/message"},
		{"long key", map[string]string{strings.Repeat("k", 65): "x"}, "/message"},
		{"invalid key", map[string]string{"\xff": "x"}, "/message"},
		{"hidden key", map[string]string{"f" + string(rune(0x200b)) + "r": "x"}, "/message"},
		{"empty", map[string]string{"fr": ""}, "/message/fr"},
		{"too long", map[string]string{"en": long + "e"}, "/message/en"},
		{"invalid UTF-8", map[string]string{"en": "a\xffb"}, "/message/en"},
		{"carriage return", map[string]string{"en": "a\r\nb"}, "/message/en"},
		{"tab", map[string]string{"en": "a\tb"}, "/message/en"},
		{"NUL", map[string]string{"en": "a\x00b"}, "/message/en"},
		{"C1 control", map[string]string{"en": "a\u0085b"}, "/message/en"},
		{"line separator", map[string]string{"en": "a" + string(rune(0x2028)) + "b"}, "/message/en"},
		{"bidi override", map[string]string{"en": "a" + string(rune(0x202e)) + "b"}, "/message/en"},
		{"first in key order", map[string]string{"fr": "", "en": ""}, "/message/en"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := m.Set(ctx, superAdmin, true, tt.messages, clientIP)
			var inv *maintenance.InvalidError
			if !errors.As(err, &inv) || inv.Field != tt.field || !errors.Is(err, maintenance.ErrInvalid) {
				t.Fatalf("Set = %v, want field %s", err, tt.field)
			}
			if !strings.Contains(err.Error(), tt.field) {
				t.Errorf("error text %q", err.Error())
			}
		})
	}
	if repo.updates != 0 || m.Active() {
		t.Errorf("%d updates after refused input", repo.updates)
	}
	// The limits themselves are accepted.
	if _, err := m.Set(ctx, superAdmin, true, map[string]string{"en": long, "fr": "x\ny"}, clientIP); err != nil {
		t.Errorf("valid messages refused: %v", err)
	}
}

// TestFailures checks the errors of the repository and of the audit: the
// state is unchanged.
func TestFailures(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("database down")
	if _, err := maintenance.New(ctx, &fakeRepo{getErr: boom}, &fakeAuditor{}, maintenance.Options{}); !errors.Is(err, boom) {
		t.Errorf("New with a failing repository: %v", err)
	}
	if _, err := maintenance.New(ctx, nil, &fakeAuditor{}, maintenance.Options{}); err == nil {
		t.Error("New without repository")
	}
	if _, err := maintenance.New(ctx, &fakeRepo{}, nil, maintenance.Options{}); err == nil {
		t.Error("New without auditor")
	}

	repo := &fakeRepo{updateErr: boom}
	m, err := maintenance.New(ctx, repo, &fakeAuditor{}, maintenance.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Set(ctx, superAdmin, true, nil, clientIP); !errors.Is(err, boom) || m.Active() {
		t.Errorf("Set with a failing update: %v (active %v)", err, m.Active())
	}
	m, err = maintenance.New(ctx, &fakeRepo{}, &fakeAuditor{err: boom}, maintenance.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Set(ctx, superAdmin, true, nil, clientIP); !errors.Is(err, boom) || m.Active() {
		t.Errorf("Set with a failing audit: %v (active %v)", err, m.Active())
	}
}

// TestAuditRollback checks on both engines that a failing audit rolls the
// change back.
func TestAuditRollback(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db := openDB(t, e)
		boom := errors.New("audit down")
		m, err := maintenance.New(ctx, db.SystemSettings(), &fakeAuditor{err: boom}, maintenance.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.Set(ctx, superAdmin, true, map[string]string{"en": "x"}, clientIP); !errors.Is(err, boom) {
			t.Fatalf("Set = %v", err)
		}
		row, err := db.SystemSettings().Get(ctx)
		if err != nil || row.MaintenanceEnabled || len(row.MaintenanceMessage) != 0 {
			t.Fatalf("stored %+v, %v", row, err)
		}
	})
}

// TestConcurrentAccess runs readers against changes (race detector).
func TestConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	m, err := maintenance.New(ctx, &fakeRepo{}, &fakeAuditor{}, maintenance.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 50 {
				_, _ = m.Set(ctx, superAdmin, i%2 == 0, map[string]string{"en": "x"}, clientIP)
				m.Force(i%2 == 1)
			}
		}()
		go func() {
			defer wg.Done()
			for range 200 {
				_ = m.Active()
				_ = m.Message("en", "fr")
				_ = m.State()
			}
		}()
	}
	wg.Wait()
}

// fakeRepo is an in-memory Repository.
type fakeRepo struct {
	mu        sync.Mutex
	row       store.SystemSettingsRow
	getErr    error
	updateErr error
	updates   int
}

func (f *fakeRepo) Get(context.Context) (store.SystemSettingsRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.row, f.getErr
}

func (f *fakeRepo) UpdateTx(_ context.Context, fn func(*store.SystemTx, *store.SystemSettingsRow) error) (store.SystemSettingsRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.updateErr != nil {
		return store.SystemSettingsRow{}, f.updateErr
	}
	next := f.row
	next.MaintenanceMessage = maps.Clone(f.row.MaintenanceMessage)
	if err := fn(nil, &next); err != nil {
		return store.SystemSettingsRow{}, err
	}
	if next.MaintenanceEnabled && next.MaintenanceSince.IsZero() {
		next.MaintenanceSince = storeNow
	}
	if !next.MaintenanceEnabled {
		next.MaintenanceSince = time.Time{}
	}
	f.updates++
	f.row = next
	return next, nil
}

// fakeAuditor records nothing, or fails.
type fakeAuditor struct{ err error }

func (f *fakeAuditor) RecordTx(context.Context, *store.SystemTx, audit.Event) error { return f.err }
