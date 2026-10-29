package store_test

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

func i64p(n int64) *int64 { return &n }

func TestDepositorInternalRemote(t *testing.T) {
	t.Parallel()
	for k, want := range map[store.DepositorKind]bool{
		store.DepositorInternal: true, store.DepositorInternalRemote: true, store.DepositorExternal: false, "reply": false, "": false,
	} {
		if got := k.IsInternal(); got != want {
			t.Errorf("%q.IsInternal() = %v", k, got)
		}
	}
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		a := newTenant(t, db, "transfer.entity-a.example.com")
		inv := mustInvitation(t, db, a.ID)

		// Deposit sessions: the internal invariants.
		s := newSession(t, senderAlice)
		s.Kind = store.DepositorInternalRemote
		if err := db.DepositSessions().Create(ctx, a.ID, s); err != nil {
			t.Fatalf("Create(remote session): %v", err)
		}
		got, err := db.DepositSessions().GetByTokenHash(ctx, a.ID, s.TokenHash, fixedNow)
		if err != nil || got.Kind != store.DepositorInternalRemote || got.InvitationID != "" {
			t.Errorf("GetByTokenHash = %+v, %v", got, err)
		}
		bad := newSession(t, senderAlice)
		bad.Kind, bad.InvitationID = store.DepositorInternalRemote, inv.ID
		wantErr(t, "Create(remote session with invitation)", db.DepositSessions().Create(ctx, a.ID, bad), store.ErrInvalid)

		// Transfers: no invitation, an API token allowed.
		tr := newTransfer()
		tr.SenderKind = store.DepositorInternalRemote
		d := mustTransfer(t, db, a.ID, tr)
		if d.SenderKind != store.DepositorInternalRemote {
			t.Errorf("SenderKind = %q", d.SenderKind)
		}
		tok := mustAPIToken(t, db, a.ID, newAPIToken(t))
		byToken := newTransfer()
		byToken.SenderKind, byToken.APITokenID = store.DepositorInternalRemote, tok.ID
		mustTransfer(t, db, a.ID, byToken)
		for name, mutate := range map[string]func(*store.Transfer){
			"remote with invitation": func(tr *store.Transfer) {
				tr.SenderKind, tr.InvitationID = store.DepositorInternalRemote, inv.ID
			},
			"external with token": func(tr *store.Transfer) {
				tr.SenderKind, tr.InvitationID, tr.APITokenID = store.DepositorExternal, inv.ID, tok.ID
			},
		} {
			x := newTransfer()
			mutate(&x)
			fl := newFile(t, db, a.ID, "x.bin", 1)
			err := inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
				return db.Transfers().CreateTx(ctx, tx, x, []string{"bob@partner.example.org"}, []store.TransferFile{fl})
			})
			wantErr(t, "CreateTx("+name+")", err, store.ErrInvalid)
		}

		// Ownership: the kind must match.
		remote := store.Depositor{Email: "ALICE@entity-a.example.com", Kind: store.DepositorInternalRemote}
		internal := store.Depositor{Email: senderAlice, Kind: store.DepositorInternal}
		if !remote.Owns(d.Transfer) || internal.Owns(d.Transfer) {
			t.Error("Owns does not separate internal and internal_remote")
		}
	})
}

// fullAbuseSettings returns settings with every rule enabled.
func fullAbuseSettings() store.AbuseSettings {
	return store.AbuseSettings{
		MaxDailyBytesPerSender: i64p(5 << 30), MaxDailyTransfersPerSender: intp(20), MaxRecipientsPerTransfer: intp(50),
		BlockOnExceed: true, UnusualVolumePct: intp(300), UnusualMinHistoryDays: 10,
		LargeExternalTransferBytes: i64p(1 << 30), OfficeStartMinute: intp(8 * 60), OfficeEndMinute: intp(18 * 60),
		OfficeWeekdays: 63, TimeZone: "Europe/Paris", MaxInvitationsPerInviter: 7,
		ExternalMaxDailyBytes: i64p(2 << 30), ExternalMaxDailyDeposits: intp(3),
		UpdatedBy: id.New(id.Admin),
	}
}

func TestAbuseSettingsValidate(t *testing.T) {
	t.Parallel()
	if err := store.DefaultAbuseSettings().Validate(); err != nil {
		t.Errorf("defaults: %v", err)
	}
	if err := fullAbuseSettings().Validate(); err != nil {
		t.Errorf("full: %v", err)
	}
	edge := store.DefaultAbuseSettings()
	edge.UnusualVolumePct, edge.UnusualMinHistoryDays = intp(store.MaxUnusualVolumePct), store.MaxUnusualMinHistoryDays
	edge.OfficeStartMinute, edge.OfficeEndMinute = intp(0), intp(store.MaxOfficeMinute)
	edge.OfficeWeekdays, edge.MaxInvitationsPerInviter = store.AllWeekdays, store.MaxInvitationsPerInviterLimit
	edge.TimeZone = strings.Repeat("é", store.MaxAbuseTimeZoneLen)
	edge.MaxDailyTransfersPerSender = intp(math.MaxInt32)
	if err := edge.Validate(); err != nil {
		t.Errorf("edge: %v", err)
	}
	for name, mutate := range map[string]func(*store.AbuseSettings){
		"bytes zero":         func(s *store.AbuseSettings) { s.MaxDailyBytesPerSender = i64p(0) },
		"transfers zero":     func(s *store.AbuseSettings) { s.MaxDailyTransfersPerSender = intp(0) },
		"transfers huge":     func(s *store.AbuseSettings) { s.MaxDailyTransfersPerSender = intp(math.MaxInt32 + 1) },
		"recipients neg":     func(s *store.AbuseSettings) { s.MaxRecipientsPerTransfer = intp(-1) },
		"pct low":            func(s *store.AbuseSettings) { s.UnusualVolumePct = intp(149) },
		"pct high":           func(s *store.AbuseSettings) { s.UnusualVolumePct = intp(10001) },
		"history zero":       func(s *store.AbuseSettings) { s.UnusualMinHistoryDays = 0 },
		"history high":       func(s *store.AbuseSettings) { s.UnusualMinHistoryDays = 31 },
		"large zero":         func(s *store.AbuseSettings) { s.LargeExternalTransferBytes = i64p(0) },
		"start only":         func(s *store.AbuseSettings) { s.OfficeEndMinute = nil },
		"end only":           func(s *store.AbuseSettings) { s.OfficeStartMinute = nil },
		"start negative":     func(s *store.AbuseSettings) { s.OfficeStartMinute = intp(-1) },
		"end after midnight": func(s *store.AbuseSettings) { s.OfficeEndMinute = intp(1441) },
		"start after end":    func(s *store.AbuseSettings) { s.OfficeStartMinute, s.OfficeEndMinute = intp(600), intp(600) },
		"weekdays neg":       func(s *store.AbuseSettings) { s.OfficeWeekdays = -1 },
		"weekdays high":      func(s *store.AbuseSettings) { s.OfficeWeekdays = 128 },
		"zone empty":         func(s *store.AbuseSettings) { s.TimeZone = "" },
		"zone long":          func(s *store.AbuseSettings) { s.TimeZone = strings.Repeat("a", 65) },
		"zone control":       func(s *store.AbuseSettings) { s.TimeZone = "UTC\n" },
		"invitations zero":   func(s *store.AbuseSettings) { s.MaxInvitationsPerInviter = 0 },
		"invitations high":   func(s *store.AbuseSettings) { s.MaxInvitationsPerInviter = 1001 },
		"external bytes":     func(s *store.AbuseSettings) { s.ExternalMaxDailyBytes = i64p(-5) },
		"external deposits":  func(s *store.AbuseSettings) { s.ExternalMaxDailyDeposits = intp(0) },
		"updater":            func(s *store.AbuseSettings) { s.UpdatedBy = "alice" },
	} {
		s := fullAbuseSettings()
		mutate(&s)
		wantErr(t, "Validate("+name+")", s.Validate(), store.ErrInvalid)
	}
}

// FuzzAbuseSettingsValidate checks that Validate never panics and accepts
// exactly the settings within the checks of tenant_abuse_settings.
func FuzzAbuseSettingsValidate(f *testing.F) {
	f.Add(int64(1), 1, 1, 150, 7, int64(1), 0, 1440, 31, "UTC", 20, int64(1), 1, true)
	f.Add(int64(0), 0, -1, 10001, 31, int64(-1), 600, 600, 128, "", 1001, int64(0), 0, false)
	f.Fuzz(func(t *testing.T, bytes int64, transfers, rcpts, pct, history int, large int64, start, end, days int,
		zone string, invites int, extBytes int64, extDeps int, office bool,
	) {
		s := store.AbuseSettings{
			MaxDailyBytesPerSender: &bytes, MaxDailyTransfersPerSender: &transfers, MaxRecipientsPerTransfer: &rcpts,
			UnusualVolumePct: &pct, UnusualMinHistoryDays: history, LargeExternalTransferBytes: &large,
			OfficeWeekdays: days, TimeZone: zone, MaxInvitationsPerInviter: invites,
			ExternalMaxDailyBytes: &extBytes, ExternalMaxDailyDeposits: &extDeps,
		}
		if office {
			s.OfficeStartMinute, s.OfficeEndMinute = &start, &end
		}
		in32 := func(n int) bool { return n > 0 && n <= math.MaxInt32 }
		want := bytes > 0 && in32(transfers) && in32(rcpts) && pct >= 150 && pct <= 10000 &&
			history >= 1 && history <= 30 && large > 0 && (!office || (start >= 0 && end <= 1440 && start < end)) &&
			days >= 0 && days <= 127 && zone != "" && validZone(zone) && invites >= 1 && invites <= 1000 &&
			extBytes > 0 && in32(extDeps)
		err := s.Validate()
		if (err == nil) != want {
			t.Fatalf("Validate(%+v) = %v, want ok %v", s, err, want)
		}
		if err != nil && !errors.Is(err, store.ErrInvalid) {
			t.Fatalf("Validate error %v is not ErrInvalid", err)
		}
	})
}

// validZone is the time zone text rule of AbuseSettings.Validate: valid
// UTF-8 of at most 64 characters on one line.
func validZone(s string) bool {
	if strings.ToValidUTF8(s, "") != s || len([]rune(s)) > store.MaxAbuseTimeZoneLen {
		return false
	}
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) || r == 0x2028 || r == 0x2029 {
			return false
		}
	}
	return true
}

func TestAbuseSettings(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.AbuseSettings()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")

		// A new tenant has the seeded defaults; an unknown one gets them too.
		for _, tid := range []tenant.ID{a.ID, tenant.ID(id.New(id.Tenant))} {
			got, err := repo.Get(ctx, tid)
			if err != nil || !reflect.DeepEqual(got, store.DefaultAbuseSettings()) {
				t.Fatalf("Get(new) = %+v, %v", got, err)
			}
		}

		in := fullAbuseSettings()
		out, err := repo.Put(ctx, a.ID, in)
		if err != nil {
			t.Fatalf("Put: %v", err)
		}
		want := in
		want.UpdatedAt = msNow
		if !reflect.DeepEqual(out, want) {
			t.Errorf("Put = %+v, want %+v", out, want)
		}
		if got, err := repo.Get(ctx, a.ID); err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("Get = %+v, %v", got, err)
		}
		err = inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			got, err := repo.GetTx(ctx, tx)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("GetTx = %+v", got)
			}
			return err
		})
		if err != nil {
			t.Errorf("GetTx: %v", err)
		}

		// Clearing every threshold, with an explicit time.
		cleared := store.DefaultAbuseSettings()
		cleared.UpdatedAt = fixedNow.Add(time.Hour)
		if out, err := repo.Put(ctx, a.ID, cleared); err != nil || out.UpdatedAt != msNow.Add(time.Hour) || out.MaxDailyBytesPerSender != nil {
			t.Fatalf("Put(cleared) = %+v, %v", out, err)
		}
		if _, err := repo.Put(ctx, a.ID, in); err != nil {
			t.Fatal(err)
		}

		// Isolation: B keeps its own row, and its change leaves A intact.
		if got, err := repo.Get(ctx, b.ID); err != nil || !reflect.DeepEqual(got, store.DefaultAbuseSettings()) {
			t.Errorf("Get(B) = %+v, %v", got, err)
		}
		other := store.DefaultAbuseSettings()
		other.MaxInvitationsPerInviter = 1
		if _, err := repo.Put(ctx, b.ID, other); err != nil {
			t.Fatal(err)
		}
		if got, _ := repo.Get(ctx, a.ID); !reflect.DeepEqual(got, want) {
			t.Errorf("Get(A) after Put(B) = %+v", got)
		}
		if got, _ := repo.Get(ctx, b.ID); got.MaxInvitationsPerInviter != 1 {
			t.Errorf("Get(B) = %+v", got)
		}

		// Invalid settings change nothing.
		badSettings := in
		badSettings.TimeZone = ""
		_, err = repo.Put(ctx, a.ID, badSettings)
		wantErr(t, "Put(invalid)", err, store.ErrInvalid)
		if got, _ := repo.Get(ctx, a.ID); !reflect.DeepEqual(got, want) {
			t.Errorf("Get(A) after invalid Put = %+v", got)
		}
		_, err = repo.Put(ctx, tenant.ID(id.New(id.Tenant)), in)
		wantErr(t, "Put(unknown tenant)", err, store.ErrNotFound)
		_, err = repo.Put(ctx, badTenant, in)
		wantErr(t, "Put(bad tenant)", err, store.ErrInvalid)
		_, err = repo.Get(ctx, badTenant)
		wantErr(t, "Get(bad tenant)", err, store.ErrInvalid)

		// Deleting the tenant cascades.
		if err := db.Tenants().Delete(ctx, b.ID); err != nil {
			t.Fatal(err)
		}
		if got, _ := repo.Get(ctx, b.ID); got.MaxInvitationsPerInviter != store.DefaultMaxInvitationsPerInviter {
			t.Errorf("settings of a deleted tenant: %+v", got)
		}
	})
}

func TestAbuseRuleValid(t *testing.T) {
	t.Parallel()
	for _, r := range []store.AbuseRule{
		store.AbuseRuleDailyBytes, store.AbuseRuleDailyTransfers, store.AbuseRuleRecipients, store.AbuseRuleUnusualVolume,
		store.AbuseRuleLargeExternal, store.AbuseRuleOffHours, store.AbuseRuleInvitations, store.AbuseRuleExternalQuota,
	} {
		if !r.Valid() {
			t.Errorf("%q not valid", r)
		}
	}
	if store.AbuseRule("bogus").Valid() || store.AbuseRule("").Valid() {
		t.Error("unknown rule valid")
	}
}

func TestAbuseAlerts(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.AbuseAlerts()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		tryKind := func(tid tenant.ID, email string, rule store.AbuseRule, day string, blocked bool, now time.Time) (bool, error) {
			var ok bool
			err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
				var err error
				ok, err = repo.TryInsertTx(ctx, tx, email, rule, day, blocked, now)
				return err
			})
			return ok, err
		}
		try := func(tid tenant.ID, email string, rule store.AbuseRule, day string, now time.Time) (bool, error) {
			return tryKind(tid, email, rule, day, false, now)
		}
		const day = "2026-10-19"
		old := fixedNow.Add(-store.AbuseAlertRetention - time.Minute)
		for _, c := range []struct {
			name, email, day string
			tid              tenant.ID
			rule             store.AbuseRule
			blocked          bool
			now              time.Time
			want             bool
		}{
			{"first", "Alice@Entity-A.example.com", day, a.ID, store.AbuseRuleDailyBytes, false, fixedNow, true},
			{"again", senderAlice, day, a.ID, store.AbuseRuleDailyBytes, false, fixedNow, false},
			// An alert-only alert never masks a refusal, and conversely.
			{"blocked after alert", senderAlice, day, a.ID, store.AbuseRuleDailyBytes, true, fixedNow, true},
			{"blocked again", senderAlice, day, a.ID, store.AbuseRuleDailyBytes, true, fixedNow, false},
			{"alert after blocked", "dave@entity-a.example.com", day, a.ID, store.AbuseRuleRecipients, true, fixedNow, true},
			{"alert after blocked 2", "dave@entity-a.example.com", day, a.ID, store.AbuseRuleRecipients, false, fixedNow, true},
			{"other rule", senderAlice, day, a.ID, store.AbuseRuleOffHours, false, old, true},
			{"other day", senderAlice, "2026-10-18", a.ID, store.AbuseRuleDailyBytes, false, old, true},
			{"other sender", "bob@entity-a.example.com", day, a.ID, store.AbuseRuleDailyBytes, false, old, true},
			{"other tenant", senderAlice, day, b.ID, store.AbuseRuleDailyBytes, false, old, true},
			{"other tenant again", senderAlice, day, b.ID, store.AbuseRuleDailyBytes, false, fixedNow, false},
			{"zero time", "carol@entity-a.example.com", day, a.ID, store.AbuseRuleInvitations, false, time.Time{}, true},
		} {
			got, err := tryKind(c.tid, c.email, c.rule, c.day, c.blocked, c.now)
			if err != nil || got != c.want {
				t.Errorf("TryInsertTx(%s) = %v, %v; want %v", c.name, got, err, c.want)
			}
		}
		for name, c := range map[string]struct {
			email, day string
			rule       store.AbuseRule
		}{
			"email":     {"nope", day, store.AbuseRuleDailyBytes},
			"rule":      {senderAlice, day, "bogus"},
			"day short": {senderAlice, "2026-1-19", store.AbuseRuleDailyBytes},
			"day bad":   {senderAlice, "2026-13-19", store.AbuseRuleDailyBytes},
		} {
			_, err := try(a.ID, c.email, c.rule, c.day, fixedNow)
			wantErr(t, "TryInsertTx("+name+")", err, store.ErrInvalid)
		}

		// Purge: only A's rows older than the retention (3 of them).
		if n, err := repo.Purge(ctx, a.ID, fixedNow); err != nil || n != 3 {
			t.Errorf("Purge(A) = %d, %v; want 3", n, err)
		}
		if ok, _ := try(a.ID, senderAlice, store.AbuseRuleOffHours, day, fixedNow); !ok {
			t.Error("purged alert still deduplicated")
		}
		if ok, _ := try(b.ID, senderAlice, store.AbuseRuleDailyBytes, day, fixedNow); ok {
			t.Error("Purge(A) deleted a row of B")
		}
		_, err := repo.Purge(ctx, badTenant, fixedNow)
		wantErr(t, "Purge(bad tenant)", err, store.ErrInvalid)

		// Erasure: alice's rows of A only.
		var n int64
		err = inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			var err error
			n, err = repo.DeleteByEmailTx(ctx, tx, "ALICE@entity-a.example.com")
			return err
		})
		if err != nil || n != 3 {
			t.Errorf("DeleteByEmailTx = %d, %v; want 3", n, err)
		}
		if ok, _ := try(a.ID, senderAlice, store.AbuseRuleDailyBytes, day, fixedNow); !ok {
			t.Error("erased alert still deduplicated")
		}
		if ok, _ := try(a.ID, "carol@entity-a.example.com", store.AbuseRuleInvitations, day, fixedNow); ok {
			t.Error("DeleteByEmailTx deleted another address")
		}
		if ok, _ := try(b.ID, senderAlice, store.AbuseRuleDailyBytes, day, fixedNow); ok {
			t.Error("DeleteByEmailTx(A) deleted a row of B")
		}
		err = inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			_, err := repo.DeleteByEmailTx(ctx, tx, "nope")
			return err
		})
		wantErr(t, "DeleteByEmailTx(bad)", err, store.ErrInvalid)
	})
}

func TestSenderActivity(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		transfers := db.Transfers()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		extend := func(trfID string, now time.Time) {
			t.Helper()
			err := inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
				_, err := transfers.ExtendTx(ctx, tx, trfID, senderAlice, fixedNow.Add(20*24*time.Hour), now)
				return err
			})
			if err != nil {
				t.Fatalf("ExtendTx: %v", err)
			}
		}
		// 10-byte transfers: t1 created now and extended a minute later
		// (counted once), t2 created now and extended 2 days later, t3
		// external, t6 internal_remote created 2 hours earlier; others of
		// bob and of tenant B.
		t1 := availableTransfer(t, db, a.ID, false)
		extend(t1.ID, fixedNow.Add(time.Minute))
		t2 := availableTransfer(t, db, a.ID, false)
		extend(t2.ID, fixedNow.Add(48*time.Hour))
		ext := newTransfer()
		ext.SenderKind, ext.InvitationID = store.DepositorExternal, mustInvitation(t, db, a.ID).ID
		mustTransfer(t, db, a.ID, ext)
		remote := newTransfer()
		remote.SenderKind, remote.CreatedAt = store.DepositorInternalRemote, fixedNow.Add(-2*time.Hour)
		t6 := mustTransfer(t, db, a.ID, remote)
		bob := newTransfer()
		bob.SenderEmail = "bob@entity-a.example.com"
		mustTransfer(t, db, a.ID, bob)
		availableTransfer(t, db, b.ID, false)

		window := func(from, to time.Duration) (time.Time, time.Time) { return fixedNow.Add(from), fixedNow.Add(to) }
		for _, c := range []struct {
			name     string
			tid      tenant.ID
			from, to time.Duration
			kinds    []store.DepositorKind
			bytes    int64
			count    int
		}{
			{"today", a.ID, -time.Hour, time.Hour, nil, 30, 3},
			{"today internal", a.ID, -time.Hour, time.Hour, []store.DepositorKind{store.DepositorInternal}, 20, 2},
			{"today external", a.ID, -time.Hour, time.Hour, []store.DepositorKind{store.DepositorExternal}, 10, 1},
			{"extension day", a.ID, 47 * time.Hour, 49 * time.Hour, []store.DepositorKind{}, 10, 1},
			{"remote", a.ID, -3 * time.Hour, -time.Hour, []store.DepositorKind{store.DepositorInternal, store.DepositorInternalRemote}, 10, 1},
			{"remote excluded", a.ID, -3 * time.Hour, -time.Hour, []store.DepositorKind{store.DepositorInternal}, 0, 0},
			{"end excluded", a.ID, -3 * time.Hour, -2 * time.Hour, nil, 0, 0},
			{"tenant B", b.ID, -time.Hour, time.Hour, nil, 10, 1},
		} {
			start, end := window(c.from, c.to)
			bytes, count, err := transfers.SenderActivity(ctx, c.tid, "Alice@Entity-A.example.com", start, end, c.kinds)
			if err != nil || bytes != c.bytes || count != c.count {
				t.Errorf("SenderActivity(%s) = %d, %d, %v; want %d, %d", c.name, bytes, count, err, c.bytes, c.count)
			}
			err = inTx(t, db, c.tid, func(tx *store.ScopedTx) error {
				bytes, count, err := transfers.SenderActivityTx(ctx, tx, senderAlice, start, end, c.kinds)
				if bytes != c.bytes || count != c.count {
					t.Errorf("SenderActivityTx(%s) = %d, %d", c.name, bytes, count)
				}
				return err
			})
			if err != nil {
				t.Errorf("SenderActivityTx(%s): %v", c.name, err)
			}
		}
		start, end := window(-time.Hour, time.Hour)
		_, _, err := transfers.SenderActivity(ctx, a.ID, senderAlice, end, start, nil)
		wantErr(t, "SenderActivity(empty window)", err, store.ErrInvalid)
		_, _, err = transfers.SenderActivity(ctx, a.ID, "nope", start, end, nil)
		wantErr(t, "SenderActivity(bad address)", err, store.ErrInvalid)
		_, _, err = transfers.SenderActivity(ctx, badTenant, senderAlice, start, end, nil)
		wantErr(t, "SenderActivity(bad tenant)", err, store.ErrInvalid)
		err = inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			_, _, err := transfers.SenderActivityTx(ctx, tx, senderAlice, start, start, nil)
			return err
		})
		wantErr(t, "SenderActivityTx(empty window)", err, store.ErrInvalid)

		// History: newest first, capped, per tenant.
		hist, err := transfers.SenderHistory(ctx, a.ID, "ALICE@entity-a.example.com", fixedNow.Add(-3*time.Hour), 10)
		if err != nil || len(hist) != 4 || hist[3].CreatedAt != t6.CreatedAt || hist[0].CreatedAt != msNow || hist[0].TotalBytes != 10 {
			t.Errorf("SenderHistory = %+v, %v", hist, err)
		}
		if hist, err := transfers.SenderHistory(ctx, a.ID, senderAlice, fixedNow.Add(-time.Hour), 2); err != nil || len(hist) != 2 {
			t.Errorf("SenderHistory(limit 2) = %+v, %v", hist, err)
		}
		if hist, err := transfers.SenderHistory(ctx, b.ID, senderAlice, fixedNow.Add(-3*time.Hour), 10); err != nil || len(hist) != 1 {
			t.Errorf("SenderHistory(B) = %+v, %v", hist, err)
		}
		if hist, err := transfers.SenderHistory(ctx, a.ID, "nobody@entity-a.example.com", time.Time{}, 10); err != nil || hist == nil || len(hist) != 0 {
			t.Errorf("SenderHistory(nobody) = %+v, %v", hist, err)
		}
		for name, run := range map[string]func() error{
			"limit 0": func() error { _, err := transfers.SenderHistory(ctx, a.ID, senderAlice, fixedNow, 0); return err },
			"limit high": func() error {
				_, err := transfers.SenderHistory(ctx, a.ID, senderAlice, fixedNow, store.MaxSenderHistoryRows+1)
				return err
			},
			"bad address": func() error { _, err := transfers.SenderHistory(ctx, a.ID, "nope", fixedNow, 1); return err },
			"bad tenant":  func() error { _, err := transfers.SenderHistory(ctx, badTenant, senderAlice, fixedNow, 1); return err },
		} {
			wantErr(t, "SenderHistory("+name+")", run(), store.ErrInvalid)
		}
	})
}

// newAbuseReport returns a valid unverified report of a shared link.
func newAbuseReport(trfID string) store.AbuseReport {
	return store.AbuseReport{
		TransferID: trfID, SenderEmail: "Alice@Entity-A.example.com",
		ReporterIP: netip.MustParseAddr("203.0.113.7"), Category: store.AbuseCategoryPhishing,
		Message: "Looks like phishing.\nPlease check.",
	}
}

// linkReport returns a valid report through a recipient link, verified
// when reporter is not "".
func linkReport(position int, reporter string) store.AbuseReport {
	r := newAbuseReport(id.New(id.Transfer))
	r.RecipientLinkID, r.RecipientPosition = id.New(id.RecipientLink), intp(position)
	r.ReporterEmail, r.ReporterVerified = reporter, reporter != ""
	return r
}

func TestAbuseReportsCreateAndGet(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.AbuseReports()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		limits := store.DefaultAbuseReportLimits()

		shared := newAbuseReport(id.New(id.Transfer))
		shared.ReporterIP = netip.MustParseAddr("::ffff:203.0.113.7")
		got, err := repo.Create(ctx, a.ID, shared, limits, time.Time{})
		if err != nil {
			t.Fatalf("Create(shared): %v", err)
		}
		want := shared
		want.ID, want.SenderEmail, want.Status, want.CreatedAt = got.ID, senderAlice, store.AbuseReportOpen, msNow
		want.ReporterIP = netip.MustParseAddr("203.0.113.7")
		if !id.Valid(id.AbuseReport, got.ID) || !reflect.DeepEqual(got, want) {
			t.Errorf("Create = %+v, want %+v", got, want)
		}
		if read, err := repo.Get(ctx, a.ID, got.ID); err != nil || !reflect.DeepEqual(read, want) {
			t.Errorf("Get = %+v, %v", read, err)
		}

		verified := linkReport(1, "Bob@Partner.example.org")
		verified.ID = id.New(id.AbuseReport)
		var vgot store.AbuseReport
		err = inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
			var err error
			vgot, err = repo.CreateTx(ctx, tx, verified, limits, fixedNow)
			return err
		})
		if err != nil || vgot.ID != verified.ID || vgot.ReporterEmail != "bob@partner.example.org" || !vgot.ReporterVerified ||
			*vgot.RecipientPosition != 1 {
			t.Fatalf("CreateTx(verified) = %+v, %v", vgot, err)
		}
		if read, err := repo.Get(ctx, a.ID, vgot.ID); err != nil || !reflect.DeepEqual(read, vgot) {
			t.Errorf("Get(verified) = %+v, %v", read, err)
		}

		// Isolation: B never reads A's reports.
		_, err = repo.Get(ctx, b.ID, got.ID)
		wantErr(t, "Get(from B)", err, store.ErrNotFound)
		if page, err := repo.List(ctx, b.ID, "", 0, ""); err != nil || len(page.Items) != 0 {
			t.Errorf("List(B) = %+v, %v", page, err)
		}

		// A duplicate ID is a conflict.
		dup := linkReport(0, "")
		dup.ID = verified.ID
		_, err = repo.Create(ctx, a.ID, dup, limits, fixedNow)
		wantErr(t, "Create(duplicate)", err, store.ErrConflict)
		_, err = repo.Create(ctx, tenant.ID(id.New(id.Tenant)), linkReport(0, ""), limits, fixedNow)
		wantErr(t, "Create(unknown tenant)", err, store.ErrNotFound)
		_, err = repo.Create(ctx, badTenant, linkReport(0, ""), limits, fixedNow)
		wantErr(t, "Create(bad tenant)", err, store.ErrInvalid)
		_, err = repo.Get(ctx, badTenant, got.ID)
		wantErr(t, "Get(bad tenant)", err, store.ErrInvalid)
		_, err = repo.Get(ctx, a.ID, "abr_nope")
		wantErr(t, "Get(malformed)", err, store.ErrNotFound)

		// Invalid reports.
		for name, mutate := range map[string]func(*store.AbuseReport){
			"id":                   func(r *store.AbuseReport) { r.ID = id.New(id.Transfer) },
			"transfer":             func(r *store.AbuseReport) { r.TransferID = "trf_x" },
			"link":                 func(r *store.AbuseReport) { r.RecipientLinkID = "rcl_x" },
			"link without pos":     func(r *store.AbuseReport) { r.RecipientPosition = nil },
			"pos without link":     func(r *store.AbuseReport) { r.RecipientLinkID = "" },
			"negative pos":         func(r *store.AbuseReport) { r.RecipientPosition = intp(-1) },
			"sender":               func(r *store.AbuseReport) { r.SenderEmail = "nope" },
			"reporter":             func(r *store.AbuseReport) { r.ReporterEmail, r.ReporterVerified = "nope", true },
			"reporter unverified":  func(r *store.AbuseReport) { r.ReporterEmail = senderAlice },
			"verified no reporter": func(r *store.AbuseReport) { r.ReporterVerified = true },
			"verified shared": func(r *store.AbuseReport) {
				r.RecipientLinkID, r.RecipientPosition, r.ReporterEmail, r.ReporterVerified = "", nil, senderAlice, true
			},
			"ip":           func(r *store.AbuseReport) { r.ReporterIP = netip.Addr{} },
			"category":     func(r *store.AbuseReport) { r.Category = "bogus" },
			"message long": func(r *store.AbuseReport) { r.Message = strings.Repeat("é", store.MaxAbuseReportTextLen+1) },
			"message nul":  func(r *store.AbuseReport) { r.Message = "a\x00b" },
			"closed":       func(r *store.AbuseReport) { r.Status = store.AbuseReportClosed },
			"closed at":    func(r *store.AbuseReport) { r.ClosedAt = fixedNow },
			"closed by":    func(r *store.AbuseReport) { r.ClosedBy = "admin" },
			"note":         func(r *store.AbuseReport) { r.Note = "x" },
		} {
			r := linkReport(0, "")
			mutate(&r)
			_, err := repo.Create(ctx, a.ID, r, limits, fixedNow)
			wantErr(t, "Create("+name+")", err, store.ErrInvalid)
		}
		edge := linkReport(0, "")
		edge.Message, edge.Category = strings.Repeat("é", store.MaxAbuseReportTextLen), store.AbuseCategoryOther
		if _, err := repo.Create(ctx, a.ID, edge, store.AbuseReportLimits{}, fixedNow); err != nil {
			t.Errorf("Create(edge) = %v", err)
		}
	})
}

func TestAbuseCategoryAndStatus(t *testing.T) {
	t.Parallel()
	for _, c := range []store.AbuseCategory{
		store.AbuseCategoryMalware, store.AbuseCategoryPhishing, store.AbuseCategoryIllegalContent,
		store.AbuseCategorySpam, store.AbuseCategoryUnknownSender, store.AbuseCategoryOther,
	} {
		if !c.Valid() {
			t.Errorf("%q not valid", c)
		}
	}
	if store.AbuseCategory("virus").Valid() || !store.AbuseReportOpen.Valid() || !store.AbuseReportClosed.Valid() ||
		store.AbuseReportStatus("pending").Valid() {
		t.Error("Valid is wrong")
	}
}

func TestAbuseReportsRateLimits(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.AbuseReports()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		limits := store.DefaultAbuseReportLimits()
		ipN := 0
		nextIP := func() netip.Addr {
			ipN++
			return netip.AddrFrom4([4]byte{198, 51, 100, byte(ipN)})
		}

		// Per shared link: 3 a day, whatever the IP.
		trf := id.New(id.Transfer)
		for i := range 3 {
			r := newAbuseReport(trf)
			r.ReporterIP = nextIP()
			if _, err := repo.Create(ctx, a.ID, r, limits, fixedNow.Add(time.Duration(i)*time.Minute)); err != nil {
				t.Fatalf("Create(shared %d): %v", i, err)
			}
		}
		r := newAbuseReport(trf)
		r.ReporterIP = nextIP()
		_, err := repo.Create(ctx, a.ID, r, limits, fixedNow.Add(time.Hour))
		wantErr(t, "Create(4th shared)", err, store.ErrAbuseReportLinkLimit)
		// Another tenant, or the same transfer through a recipient link, is
		// counted apart.
		if _, err := repo.Create(ctx, b.ID, r, limits, fixedNow.Add(time.Hour)); err != nil {
			t.Errorf("Create(shared in B) = %v", err)
		}
		viaLink := linkReport(0, "")
		viaLink.TransferID, viaLink.ReporterIP = trf, nextIP()
		if _, err := repo.Create(ctx, a.ID, viaLink, limits, fixedNow.Add(time.Hour)); err != nil {
			t.Errorf("Create(link of the same transfer) = %v", err)
		}
		// The window slides: the first report leaves it after 24 hours.
		if _, err := repo.Create(ctx, a.ID, r, limits, fixedNow.Add(store.AbuseReportLinkWindow+time.Second)); err != nil {
			t.Errorf("Create(shared next day) = %v", err)
		}

		// Per recipient link: 3 a day.
		link := linkReport(2, "")
		for i := range 3 {
			link.ReporterIP = nextIP()
			if _, err := repo.Create(ctx, a.ID, link, limits, fixedNow); err != nil {
				t.Fatalf("Create(link %d): %v", i, err)
			}
		}
		link.ReporterIP = nextIP()
		_, err = repo.Create(ctx, a.ID, link, limits, fixedNow)
		wantErr(t, "Create(4th link)", err, store.ErrAbuseReportLinkLimit)
		if _, err := repo.Create(ctx, a.ID, link, store.AbuseReportLimits{}, fixedNow); err != nil {
			t.Errorf("Create(no limits) = %v", err)
		}

		// Per IP: 5 an hour, any link.
		ip := netip.MustParseAddr("2001:db8::1")
		for i := range 5 {
			x := linkReport(0, "")
			x.ReporterIP = ip
			if _, err := repo.Create(ctx, a.ID, x, limits, fixedNow.Add(time.Duration(i)*time.Second)); err != nil {
				t.Fatalf("Create(ip %d): %v", i, err)
			}
		}
		x := linkReport(0, "")
		x.ReporterIP = ip
		_, err = repo.Create(ctx, a.ID, x, limits, fixedNow.Add(time.Minute))
		wantErr(t, "Create(6th from ip)", err, store.ErrAbuseReportIPLimit)
		// Both limits reached: the link is reported first.
		link.ReporterIP = ip
		_, err = repo.Create(ctx, a.ID, link, limits, fixedNow.Add(time.Minute))
		wantErr(t, "Create(both limits)", err, store.ErrAbuseReportLinkLimit)
		if _, err := repo.Create(ctx, b.ID, x, limits, fixedNow.Add(time.Minute)); err != nil {
			t.Errorf("Create(same ip in B) = %v", err)
		}
		if _, err := repo.Create(ctx, a.ID, x, limits, fixedNow.Add(store.AbuseReportIPWindow+time.Second)); err != nil {
			t.Errorf("Create(ip an hour later) = %v", err)
		}
	})
}

func TestAbuseReportsListAndStatus(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.AbuseReports()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		var ids []string
		for i := range 5 {
			r, err := repo.Create(ctx, a.ID, linkReport(i, ""), store.AbuseReportLimits{}, fixedNow.Add(time.Duration(i)*time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			ids = append(ids, r.ID)
		}
		if _, err := repo.Create(ctx, b.ID, linkReport(0, ""), store.AbuseReportLimits{}, fixedNow); err != nil {
			t.Fatal(err)
		}

		// Status changes.
		note := "Checked with the sender."
		closed, changed, err := repo.SetStatus(ctx, a.ID, ids[1], store.AbuseReportClosed, "admin.one", &note, fixedNow.Add(time.Hour))
		if err != nil || !changed || closed.Status != store.AbuseReportClosed || closed.ClosedBy != "admin.one" ||
			closed.ClosedAt != msNow.Add(time.Hour) || closed.Note != note {
			t.Fatalf("SetStatus(close) = %+v, %v, %v", closed, changed, err)
		}
		other := "ignored"
		same, changed, err := repo.SetStatus(ctx, a.ID, ids[1], store.AbuseReportClosed, "admin.two", &other, time.Time{})
		if err != nil || changed || !reflect.DeepEqual(same, closed) {
			t.Errorf("SetStatus(close again) = %+v, %v, %v", same, changed, err)
		}
		reopened, changed, err := repo.SetStatus(ctx, a.ID, ids[1], store.AbuseReportOpen, "", nil, time.Time{})
		if err != nil || !changed || reopened.Status != store.AbuseReportOpen || !reopened.ClosedAt.IsZero() ||
			reopened.ClosedBy != "" || reopened.Note != note {
			t.Errorf("SetStatus(reopen) = %+v, %v, %v", reopened, changed, err)
		}
		if _, changed, err := repo.SetStatus(ctx, a.ID, ids[1], store.AbuseReportOpen, "", nil, time.Time{}); err != nil || changed {
			t.Errorf("SetStatus(reopen again) = %v, %v", changed, err)
		}
		closed, _, err = repo.SetStatus(ctx, a.ID, ids[1], store.AbuseReportClosed, "admin.two", nil, time.Time{})
		if err != nil || closed.Note != note || closed.ClosedBy != "admin.two" || closed.ClosedAt != msNow {
			t.Errorf("SetStatus(close, note kept) = %+v, %v", closed, err)
		}
		empty := ""
		reopened, _, err = repo.SetStatus(ctx, a.ID, ids[1], store.AbuseReportOpen, "", &empty, time.Time{})
		if err != nil || reopened.Note != "" {
			t.Errorf("SetStatus(reopen, note cleared) = %+v, %v", reopened, err)
		}
		if _, _, err := repo.SetStatus(ctx, a.ID, ids[3], store.AbuseReportClosed, "admin.one", nil, time.Time{}); err != nil {
			t.Fatal(err)
		}
		long := strings.Repeat("n", store.MaxAbuseReportTextLen+1)
		for name, run := range map[string]func() error{
			"status": func() error {
				_, _, err := repo.SetStatus(ctx, a.ID, ids[0], "pending", "x", nil, fixedNow)
				return err
			},
			"no admin": func() error {
				_, _, err := repo.SetStatus(ctx, a.ID, ids[0], store.AbuseReportClosed, "", nil, fixedNow)
				return err
			},
			"admin long": func() error {
				_, _, err := repo.SetStatus(ctx, a.ID, ids[0], store.AbuseReportClosed, strings.Repeat("a", 65), nil, fixedNow)
				return err
			},
			"admin lines": func() error {
				_, _, err := repo.SetStatus(ctx, a.ID, ids[0], store.AbuseReportClosed, "a\nb", nil, fixedNow)
				return err
			},
			"note long": func() error {
				_, _, err := repo.SetStatus(ctx, a.ID, ids[0], store.AbuseReportOpen, "", &long, fixedNow)
				return err
			},
			"bad tenant": func() error {
				_, _, err := repo.SetStatus(ctx, badTenant, ids[0], store.AbuseReportOpen, "", nil, fixedNow)
				return err
			},
		} {
			wantErr(t, "SetStatus("+name+")", run(), store.ErrInvalid)
		}
		// Isolation: B cannot change A's report.
		_, _, err = repo.SetStatus(ctx, b.ID, ids[0], store.AbuseReportClosed, "admin.b", nil, fixedNow)
		wantErr(t, "SetStatus(from B)", err, store.ErrNotFound)
		_, _, err = repo.SetStatus(ctx, a.ID, id.New(id.AbuseReport), store.AbuseReportClosed, "admin.a", nil, fixedNow)
		wantErr(t, "SetStatus(unknown)", err, store.ErrNotFound)
		if r, _ := repo.Get(ctx, a.ID, ids[0]); r.Status != store.AbuseReportOpen {
			t.Errorf("report changed by B: %+v", r)
		}

		// Lists, newest first, paginated.
		var seen []string
		cursor := ""
		for {
			page, err := repo.List(ctx, a.ID, "", 2, cursor)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range page.Items {
				seen = append(seen, r.ID)
			}
			if page.NextCursor == "" {
				break
			}
			cursor = page.NextCursor
		}
		if !reflect.DeepEqual(seen, []string{ids[4], ids[3], ids[2], ids[1], ids[0]}) {
			t.Errorf("List = %v", seen)
		}
		if page, err := repo.List(ctx, a.ID, store.AbuseReportClosed, 0, ""); err != nil || len(page.Items) != 1 || page.Items[0].ID != ids[3] {
			t.Errorf("List(closed) = %+v, %v", page, err)
		}
		if page, err := repo.List(ctx, a.ID, store.AbuseReportOpen, 0, ""); err != nil || len(page.Items) != 4 {
			t.Errorf("List(open) = %+v, %v", page, err)
		}
		_, err = repo.List(ctx, a.ID, "pending", 0, "")
		wantErr(t, "List(bad status)", err, store.ErrInvalid)
		_, err = repo.List(ctx, a.ID, "", 0, "1:trf_x")
		wantErr(t, "List(bad cursor)", err, store.ErrInvalid)
		_, err = repo.List(ctx, badTenant, "", 0, "")
		wantErr(t, "List(bad tenant)", err, store.ErrInvalid)
	})
}

func TestAbuseReportsErasureAndPurge(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.AbuseReports()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		mk := func(tid tenant.ID, sender, reporter string, at time.Time) store.AbuseReport {
			t.Helper()
			r := linkReport(0, reporter)
			r.SenderEmail = sender
			out, err := repo.Create(ctx, tid, r, store.AbuseReportLimits{}, at)
			if err != nil {
				t.Fatal(err)
			}
			return out
		}
		const bob, carol = "bob@partner.example.org", "carol@partner.example.org"
		aliceSent := mk(a.ID, senderAlice, carol, fixedNow)
		aliceReported := mk(a.ID, bob, senderAlice, fixedNow)
		both := mk(a.ID, senderAlice, senderAlice, fixedNow)
		unrelated := mk(a.ID, bob, "", fixedNow)
		inB := mk(b.ID, senderAlice, senderAlice, fixedNow)

		pseudonym := store.PseudonymPrefix + "0123456789abcdef"
		pseudonymise := func(tid tenant.ID, email, p string) (int64, error) {
			var n int64
			err := inTxCtx(ctx, t, db, tid, func(tx *store.ScopedTx) error {
				var err error
				n, err = repo.PseudonymiseTx(ctx, tx, email, p)
				return err
			})
			return n, err
		}
		if n, err := pseudonymise(a.ID, "Alice@Entity-A.example.com", pseudonym); err != nil || n != 3 {
			t.Fatalf("PseudonymiseTx = %d, %v; want 3", n, err)
		}
		get := func(tid tenant.ID, repID string) store.AbuseReport {
			t.Helper()
			r, err := repo.Get(ctx, tid, repID)
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		if r := get(a.ID, aliceSent.ID); r.SenderEmail != pseudonym || r.ReporterEmail != carol {
			t.Errorf("sent by alice = %+v", r)
		}
		if r := get(a.ID, aliceReported.ID); r.SenderEmail != bob || r.ReporterEmail != pseudonym || !r.ReporterVerified {
			t.Errorf("reported by alice = %+v", r)
		}
		if r := get(a.ID, both.ID); r.SenderEmail != pseudonym || r.ReporterEmail != pseudonym {
			t.Errorf("both = %+v", r)
		}
		if r := get(a.ID, unrelated.ID); !reflect.DeepEqual(r, unrelated) {
			t.Errorf("unrelated = %+v", r)
		}
		if r := get(b.ID, inB.ID); !reflect.DeepEqual(r, inB) {
			t.Errorf("report of B pseudonymised: %+v", r)
		}
		if n, err := pseudonymise(a.ID, senderAlice, pseudonym); err != nil || n != 0 {
			t.Errorf("PseudonymiseTx(again) = %d, %v", n, err)
		}
		_, err := pseudonymise(a.ID, "nope", pseudonym)
		wantErr(t, "PseudonymiseTx(bad address)", err, store.ErrInvalid)
		_, err = pseudonymise(a.ID, senderAlice, "erased-xyz")
		wantErr(t, "PseudonymiseTx(bad pseudonym)", err, store.ErrInvalid)

		// Purge: 12 months, whatever the status, tenant by tenant.
		old := mk(a.ID, bob, "", fixedNow.AddDate(0, -store.AbuseReportRetentionMonths, 0).Add(-time.Second))
		if _, _, err := repo.SetStatus(ctx, a.ID, old.ID, store.AbuseReportClosed, "admin", nil, fixedNow); err != nil {
			t.Fatal(err)
		}
		edge := mk(a.ID, bob, "", fixedNow.AddDate(0, -store.AbuseReportRetentionMonths, 0))
		oldB := mk(b.ID, bob, "", fixedNow.AddDate(-2, 0, 0))
		if n, err := repo.Purge(ctx, a.ID, fixedNow); err != nil || n != 1 {
			t.Errorf("Purge(A) = %d, %v; want 1", n, err)
		}
		_, err = repo.Get(ctx, a.ID, old.ID)
		wantErr(t, "Get(purged)", err, store.ErrNotFound)
		get(a.ID, edge.ID)
		get(b.ID, oldB.ID)
		_, err = repo.Purge(ctx, badTenant, fixedNow)
		wantErr(t, "Purge(bad tenant)", err, store.ErrInvalid)

		// Deleting the tenant deletes its reports.
		if err := db.Tenants().Delete(ctx, b.ID); err != nil {
			t.Fatal(err)
		}
		_, err = repo.Get(ctx, b.ID, inB.ID)
		wantErr(t, "Get(deleted tenant)", err, store.ErrNotFound)
	})
}

func TestAbuseReportsPseudonymiseTexts(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		t.Parallel()
		ctx := context.Background()
		db := openDB(t, e)
		repo := db.AbuseReports()
		a := newTenant(t, db, "transfer.entity-a.example.com")
		b := newTenant(t, db, "transfer.entity-b.example.com")
		const bob = "bob@partner.example.org"
		mk := func(tid tenant.ID, sender, message string) store.AbuseReport {
			t.Helper()
			r := linkReport(0, "")
			r.SenderEmail, r.Message = sender, message
			out, err := repo.Create(ctx, tid, r, store.AbuseReportLimits{}, fixedNow)
			if err != nil {
				t.Fatal(err)
			}
			return out
		}
		message := "Sent by ALICE@Entity-A.example.com; write to alice@entity-a.example.com."
		text := mk(a.ID, bob, message)
		sent := mk(a.ID, senderAlice, "I am alice@entity-a.example.com")
		longer := mk(a.ID, bob, "xalice@entity-a.example.com, alice@entity-a.example.com.evil, alice@entity-a.example.community")
		noted := mk(a.ID, bob, "")
		note := "Called Alice@entity-a.example.com"
		if _, _, err := repo.SetStatus(ctx, a.ID, noted.ID, store.AbuseReportClosed, "admin", &note, fixedNow); err != nil {
			t.Fatal(err)
		}
		inB := mk(b.ID, bob, message)
		// A short address grows into the pseudonym: the text is cut.
		short := mk(a.ID, bob, strings.Repeat("x@y.example ", 83))

		pseudonym := store.PseudonymPrefix + "0123456789abcdef"
		pseudonymise := func(email string) int64 {
			t.Helper()
			var n int64
			err := inTxCtx(ctx, t, db, a.ID, func(tx *store.ScopedTx) error {
				var err error
				n, err = repo.PseudonymiseTx(ctx, tx, email, pseudonym)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
		// text, noted and sent: each report counted once.
		if n := pseudonymise(senderAlice); n != 3 {
			t.Errorf("PseudonymiseTx = %d; want 3", n)
		}
		get := func(tid tenant.ID, repID string) store.AbuseReport {
			t.Helper()
			r, err := repo.Get(ctx, tid, repID)
			if err != nil {
				t.Fatal(err)
			}
			return r
		}
		if r := get(a.ID, text.ID); r.Message != "Sent by "+pseudonym+"; write to "+pseudonym+"." || r.SenderEmail != bob {
			t.Errorf("text = %+v", r)
		}
		if r := get(a.ID, sent.ID); r.Message != "I am "+pseudonym || r.SenderEmail != pseudonym {
			t.Errorf("sent = %+v", r)
		}
		if r := get(a.ID, longer.ID); !reflect.DeepEqual(r, longer) {
			t.Errorf("longer addresses changed: %+v", r)
		}
		if r := get(a.ID, noted.ID); r.Note != "Called "+pseudonym {
			t.Errorf("noted = %+v", r)
		}
		if r := get(b.ID, inB.ID); !reflect.DeepEqual(r, inB) {
			t.Errorf("report of B pseudonymised: %+v", r)
		}
		if n := pseudonymise(senderAlice); n != 0 {
			t.Errorf("PseudonymiseTx(again) = %d", n)
		}
		if n := pseudonymise("x@y.example"); n != 1 {
			t.Errorf("PseudonymiseTx(short) = %d", n)
		}
		r := get(a.ID, short.ID)
		if utf8.RuneCountInString(r.Message) != store.MaxAbuseReportTextLen || !strings.HasPrefix(r.Message, pseudonym+" "+pseudonym) ||
			strings.Contains(r.Message, "x@y.example") {
			t.Errorf("short = %q", r.Message)
		}
	})
}
