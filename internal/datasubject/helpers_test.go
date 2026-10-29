package datasubject

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/adminauth"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/lifecycle"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/upload"
)

// Test hosts and addresses (fictitious).
const (
	hostA = "transfer.entity-a.example.com"
	hostB = "transfer.entity-b.example.com"

	// subjectInput is the address as typed by the administrator; carol is
	// its normalized form.
	subjectInput = "  Carol@Customer.Example.NET "
	carol        = "carol@customer.example.net"
	alice        = "alice@entity-a.example.com"
	dave         = "dave@partner.example.org"
	erin         = "erin@partner.example.org"
)

var (
	testStart = time.Date(2026, time.October, 22, 9, 0, 0, 0, time.UTC)
	clientIP  = netip.MustParseAddr("192.0.2.10")
	errBoom   = errors.New("boom")
)

// fakeClock is a manual clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// testHolder records the holds; err fails the next Hold.
//
// It also models the deferred mails of the antivirus worker: when
// conclude is set, each edit hold stands for a scan conclusion committed
// while it is held, whose mails are deferred to the last release; an
// erasure hold cancels them; a last release with mails still deferred
// counts one deferred send.
type testHolder struct {
	mu       sync.Mutex
	err      error
	holds    int
	releases int
	intents  []lifecycle.HoldIntent

	conclude bool
	active   int
	pending  bool
	sent     int
}

func (h *testHolder) Hold(_ context.Context, _ tenant.ID, _ string, intent lifecycle.HoldIntent) (func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.err != nil {
		err := h.err
		h.err = nil
		return nil, err
	}
	h.holds++
	h.active++
	h.intents = append(h.intents, intent)
	switch intent {
	case lifecycle.HoldForErase:
		h.pending = false
	case lifecycle.HoldForEdit:
		h.pending = h.pending || h.conclude
	}
	return func() {
		h.mu.Lock()
		h.releases++
		h.active--
		if h.active == 0 && h.pending {
			h.pending = false
			h.sent++
		}
		h.mu.Unlock()
	}, nil
}

// deferredSends returns the deferred sends of the model.
func (h *testHolder) deferredSends() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sent
}

func (h *testHolder) counts() (int, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.holds, h.releases
}

// flakyEraser wraps the sweeper: it answers busy times ErrBusy, then err
// once, before delegating.
type flakyEraser struct {
	inner TransferEraser
	mu    sync.Mutex
	busy  int
	err   error
	calls int
	// before, when set, is called with the context of each delegated
	// call.
	before func(ctx context.Context)
}

func (e *flakyEraser) EraseTransfer(ctx context.Context, tid tenant.ID, trfID string, mode lifecycle.EraseMode) (lifecycle.EraseResult, error) {
	e.mu.Lock()
	e.calls++
	if e.busy > 0 {
		e.busy--
		e.mu.Unlock()
		return 0, fmt.Errorf("%w: %s", lifecycle.ErrBusy, trfID)
	}
	if err := e.err; err != nil {
		e.err = nil
		e.mu.Unlock()
		return 0, err
	}
	before := e.before
	e.mu.Unlock()
	if before != nil {
		before(ctx)
	}
	return e.inner.EraseTransfer(ctx, tid, trfID, mode)
}

// faultRepo wraps a repo and fails the methods named in errs.
type faultRepo struct {
	repo
	mu   sync.Mutex
	errs map[string]error
	// after lets a method succeed n times before failing.
	after map[string]int
}

func (f *faultRepo) fail(method string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	err, ok := f.errs[method]
	if !ok {
		return nil
	}
	if f.after[method] > 0 {
		f.after[method]--
		return nil
	}
	return err
}

func (f *faultRepo) getTenant(ctx context.Context, tid tenant.ID) (*tenant.Tenant, error) {
	if err := f.fail("getTenant"); err != nil {
		return nil, err
	}
	return f.repo.getTenant(ctx, tid)
}

func (f *faultRepo) senderTransfers(ctx context.Context, tid tenant.ID, email string) ([]string, error) {
	if err := f.fail("senderTransfers"); err != nil {
		return nil, err
	}
	return f.repo.senderTransfers(ctx, tid, email)
}

func (f *faultRepo) recipientTransfers(ctx context.Context, tid tenant.ID, email string) ([]string, error) {
	if err := f.fail("recipientTransfers"); err != nil {
		return nil, err
	}
	return f.repo.recipientTransfers(ctx, tid, email)
}

func (f *faultRepo) invitationTransfers(ctx context.Context, tid tenant.ID, invID string) ([]string, error) {
	if err := f.fail("invitationTransfers"); err != nil {
		return nil, err
	}
	return f.repo.invitationTransfers(ctx, tid, invID)
}

func (f *faultRepo) inviteeInvitations(ctx context.Context, tid tenant.ID, email string) ([]string, error) {
	if err := f.fail("inviteeInvitations"); err != nil {
		return nil, err
	}
	return f.repo.inviteeInvitations(ctx, tid, email)
}

func (f *faultRepo) countInvitations(ctx context.Context, tid tenant.ID, email string) (int, int, error) {
	if err := f.fail("countInvitations"); err != nil {
		return 0, 0, err
	}
	return f.repo.countInvitations(ctx, tid, email)
}

func (f *faultRepo) verified(ctx context.Context, tid tenant.ID, email string) (bool, error) {
	if err := f.fail("verified"); err != nil {
		return false, err
	}
	return f.repo.verified(ctx, tid, email)
}

func (f *faultRepo) countAudit(ctx context.Context, tid tenant.ID, email string) (int, error) {
	if err := f.fail("countAudit"); err != nil {
		return 0, err
	}
	return f.repo.countAudit(ctx, tid, email)
}

func (f *faultRepo) deleteDepositRows(ctx context.Context, tid tenant.ID, email string) error {
	if err := f.fail("deleteDepositRows"); err != nil {
		return err
	}
	return f.repo.deleteDepositRows(ctx, tid, email)
}

func (f *faultRepo) deleteSenderAccess(ctx context.Context, tid tenant.ID, email string, mac []byte) (int64, error) {
	if err := f.fail("deleteSenderAccess"); err != nil {
		return 0, err
	}
	return f.repo.deleteSenderAccess(ctx, tid, email, mac)
}

func (f *faultRepo) deleteVerified(ctx context.Context, tid tenant.ID, email string) (bool, error) {
	if err := f.fail("deleteVerified"); err != nil {
		return false, err
	}
	return f.repo.deleteVerified(ctx, tid, email)
}

func (f *faultRepo) removeRecipient(ctx context.Context, tid tenant.ID, trfID, email string) (recipientOutcome, error) {
	if err := f.fail("removeRecipient"); err != nil {
		return 0, err
	}
	return f.repo.removeRecipient(ctx, tid, trfID, email)
}

func (f *faultRepo) eraseInvitations(ctx context.Context, tid tenant.ID, email, pseudonym string, now time.Time) (int64, error) {
	if err := f.fail("eraseInvitations"); err != nil {
		return 0, err
	}
	return f.repo.eraseInvitations(ctx, tid, email, pseudonym, now)
}

func (f *faultRepo) eraseAbuse(ctx context.Context, tid tenant.ID, email, pseudonym string) (int64, error) {
	if err := f.fail("eraseAbuse"); err != nil {
		return 0, err
	}
	return f.repo.eraseAbuse(ctx, tid, email, pseudonym)
}

func (f *faultRepo) pseudonymiseAudit(ctx context.Context, tid tenant.ID, email, pseudonym string) (int64, error) {
	if err := f.fail("pseudonymiseAudit"); err != nil {
		return 0, err
	}
	return f.repo.pseudonymiseAudit(ctx, tid, email, pseudonym)
}

func (f *faultRepo) scrub(ctx context.Context) error {
	if err := f.fail("scrub"); err != nil {
		return err
	}
	return f.repo.scrub(ctx)
}

func (f *faultRepo) audit(ctx context.Context, tid tenant.ID, ev audit.Event) error {
	if err := f.fail("audit"); err != nil {
		return err
	}
	return f.repo.audit(ctx, tid, ev)
}

// env is a service over a migrated database with tenants A and B, real
// storage, keys, upload engine and sweeper, a super admin and a delegated
// admin of each tenant.
type env struct {
	t       *testing.T
	db      *store.DB
	vault   *masterkey.Vault
	files   *storage.Store
	sweeper *lifecycle.Sweeper
	holder  *testHolder
	eraser  *flakyEraser
	svc     *Service
	logs    *bytes.Buffer
	sleeps  int
	clock   *fakeClock
	keys    *masterkey.Keyring
	a, b    *tenant.Tenant
	super   adminauth.Principal
	adminA  adminauth.Principal
	adminB  adminauth.Principal
}

// newEnv builds an env on engine e.
func newEnv(t *testing.T, e storetest.Engine) *env {
	t.Helper()
	ctx := context.Background()
	clock := &fakeClock{now: testStart}
	db, err := store.Open(ctx, e.Config(), store.WithClock(clock.Now))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	kr, err := masterkey.New(masterkeytest.Key(t, "datasubject"), nil)
	if err != nil {
		t.Fatal(err)
	}
	vault := masterkey.NewVault(db, kr, nil)
	files, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = files.Close() })
	ev := &env{t: t, db: db, vault: vault, files: files, holder: &testHolder{}, logs: &bytes.Buffer{}, clock: clock, keys: kr}
	logger := slog.New(slog.NewTextHandler(ev.logs, nil))
	ev.sweeper = lifecycle.New(lifecycle.Deps{
		DB: db, Vault: vault, Remover: upload.New(db, vault, files, upload.Options{}), Files: files, Holder: ev.holder,
	}, lifecycle.Options{Now: clock.Now, Logger: logger})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = ev.sweeper.Close(ctx)
		if all := ev.logs.String(); strings.Contains(all, "@") || strings.Contains(strings.ToLower(all), "carol") {
			t.Errorf("logs hold an address:\n%s", all)
		}
	})
	ev.eraser = &flakyEraser{inner: ev.sweeper}
	ev.svc, err = New(db, Options{Eraser: ev.eraser, Holder: ev.holder, Logger: logger, Now: clock.Now, Keys: kr})
	if err != nil {
		t.Fatal(err)
	}
	ev.svc.sleep = func(ctx context.Context, _ time.Duration) error {
		ev.sleeps++
		return ctx.Err()
	}
	ev.a = ev.newTenant("Entity A", hostA)
	ev.b = ev.newTenant("Entity B", hostB)
	ev.super = principal(store.RoleSuperAdmin, "root")
	ev.adminA = principal(store.RoleDelegatedAdmin, "alice-admin", ev.a.ID)
	ev.adminB = principal(store.RoleDelegatedAdmin, "bob-admin", ev.b.ID)
	return ev
}

// newTenant creates a tenant directly in the store.
func (ev *env) newTenant(name, fqdn string) *tenant.Tenant {
	ev.t.Helper()
	tn, err := ev.db.Tenants().Create(context.Background(), &tenant.Tenant{
		Name: name, FQDN: fqdn, DefaultLanguage: "en", MaxTransferBytes: 1 << 30, StorageQuotaBytes: 10 << 30,
	})
	if err != nil {
		ev.t.Fatalf("Create(%s): %v", fqdn, err)
	}
	return tn
}

// faults replaces the repo of the service with a faultRepo failing the
// given methods with errBoom.
func (ev *env) faults(methods ...string) *faultRepo {
	inner := ev.svc.repo
	if prev, ok := inner.(*faultRepo); ok {
		inner = prev.repo
	}
	f := &faultRepo{repo: inner, errs: map[string]error{}, after: map[string]int{}}
	for _, m := range methods {
		f.errs[m] = errBoom
	}
	ev.svc.repo = f
	return f
}

// tx runs fn in a write transaction of tn.
func (ev *env) tx(tn *tenant.Tenant, fn func(*store.ScopedTx) error) {
	ev.t.Helper()
	s, err := ev.db.Scoped(tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	if err := s.Tx(context.Background(), fn); err != nil {
		ev.t.Fatal(err)
	}
}

// transferState is the state a fixture transfer is left in.
type transferState int

const (
	stateUploading transferState = iota
	stateScanning
	stateAvailable
	stateDeleted
	// stateLinks is available with one link per recipient.
	stateLinks
)

// transfer stores a transfer of tn sent by sender (with the invitation
// invID when not "") to recipients, with two encrypted files on disk, in
// state st, and returns its ID.
func (ev *env) transfer(tn *tenant.Tenant, sender, invID string, recipients []string, st transferState) string {
	ev.t.Helper()
	ctx := context.Background()
	trfID := id.New(id.Transfer)
	kind := store.DepositorInternal
	if invID != "" {
		kind = store.DepositorExternal
	}
	ev.tx(tn, func(tx *store.ScopedTx) error {
		files := make([]store.TransferFile, 0, 2)
		for i := range 2 {
			f, err := ev.storeFile(ctx, tx, tn)
			if err != nil {
				return err
			}
			f.Name = fmt.Sprintf("file-%d.bin", i)
			files = append(files, f)
		}
		tr := store.Transfer{ID: trfID, SenderEmail: sender, SenderKind: kind, InvitationID: invID, ExpiryDays: 7}
		if st == stateLinks {
			tr.LinkMode = store.LinkModePerRecipient
		}
		if err := ev.db.Transfers().CreateTx(ctx, tx, tr, recipients, files); err != nil {
			return err
		}
		if st == stateUploading {
			return nil
		}
		if err := ev.db.Transfers().FinalizeTx(ctx, tx, trfID, testStart.Add(-time.Hour)); err != nil {
			return err
		}
		if st == stateScanning {
			return nil
		}
		if st == stateLinks {
			tokens := make([]store.LinkToken, len(recipients))
			for i := range tokens {
				token, err := id.NewDownloadToken()
				if err != nil {
					return err
				}
				hash := sha256.Sum256([]byte(token))
				wk, err := ev.vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte(token))
				if err != nil {
					return err
				}
				tokens[i] = store.LinkToken{Hash: hash[:], KeyID: wk}
			}
			_, err := ev.db.Transfers().MarkAvailableLinksTx(ctx, tx, trfID, tokens, testStart.Add(-time.Hour))
			return err
		}
		token, err := id.NewDownloadToken()
		if err != nil {
			return err
		}
		hash := sha256.Sum256([]byte(token))
		wk, err := ev.vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte(token))
		if err != nil {
			return err
		}
		return ev.db.Transfers().MarkAvailableTx(ctx, tx, trfID, hash[:], wk, testStart.Add(-time.Hour))
	})
	if st == stateDeleted {
		if _, err := ev.sweeper.EraseTransfer(ctx, tn.ID, trfID, lifecycle.MarkDeleted); err != nil {
			ev.t.Fatal(err)
		}
	}
	return trfID
}

// storeFile writes random bytes to a new stored file of tn and returns its
// completed row with a new data key.
func (ev *env) storeFile(ctx context.Context, tx *store.ScopedTx, tn *tenant.Tenant) (store.TransferFile, error) {
	wk, _, err := ev.vault.NewDEKTx(ctx, tx)
	if err != nil {
		return store.TransferFile{}, err
	}
	storageName := storage.NewName()
	out, err := ev.files.Create(tn.ID, storageName)
	if err != nil {
		return store.TransferFile{}, err
	}
	content := make([]byte, 64)
	_, _ = rand.Read(content)
	_, err = out.Write(content)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return store.TransferFile{}, err
	}
	upl, err := id.NewUploadToken()
	if err != nil {
		return store.TransferFile{}, err
	}
	sum := sha256.Sum256(content)
	return store.TransferFile{
		ID: id.New(id.File), Size: int64(len(content)), DEKKeyID: wk, StorageName: storageName, UploadID: upl,
		SHA256: hex.EncodeToString(sum[:]), CiphertextSize: int64(len(content)), UploadedAt: testStart.Add(-2 * time.Hour),
	}, nil
}

// invitation stores an invitation of tn for invitee issued by inviter and
// returns its ID.
func (ev *env) invitation(tn *tenant.Tenant, invitee, inviter string) string {
	ev.t.Helper()
	invID := id.New(id.Invitation)
	h := sha256.Sum256([]byte(invID))
	if err := ev.db.Invitations().Create(context.Background(), tn.ID, store.Invitation{
		ID: invID, TokenHash: h[:], Email: invitee, InvitedBy: inviter,
	}); err != nil {
		ev.t.Fatal(err)
	}
	return invID
}

// depositRows stores, for email in tn, a verified address, a challenge
// and an open deposit session (with the invitation invID when not ""), and
// returns the token hash of the session.
func (ev *env) depositRows(tn *tenant.Tenant, email, invID string) []byte {
	ev.t.Helper()
	ctx := context.Background()
	chID, err := id.NewToken(id.ChallengeTokenPrefix, id.MinTokenBytes)
	if err != nil {
		ev.t.Fatal(err)
	}
	if err := ev.db.Challenges().Create(ctx, tn.ID, store.Challenge{
		ID: chID, Email: email, CodeMAC: []byte{1}, AttemptsRemaining: 1, ClientIP: clientIP,
		InvitationID: invID, ExpiresAt: testStart.Add(15 * time.Minute),
	}); err != nil {
		ev.t.Fatal(err)
	}
	kind := store.DepositorInternal
	if invID != "" {
		kind = store.DepositorExternal
	}
	h := sha256.Sum256([]byte("session " + chID))
	if err := ev.db.DepositSessions().Create(ctx, tn.ID, store.DepositSession{
		ID: id.New(id.DepositSession), TokenHash: h[:], Email: email, Kind: kind, InvitationID: invID,
		ExpiresAt: testStart.Add(4 * time.Hour),
	}); err != nil {
		ev.t.Fatal(err)
	}
	ev.tx(tn, func(tx *store.ScopedTx) error {
		_, err := ev.db.VerifiedAddresses().UpsertTx(ctx, tx, store.VerifiedAddress{Email: email, FirstVerifiedIP: clientIP})
		return err
	})
	return h[:]
}

// auditActor appends n audit events of tn whose actor is email.
func (ev *env) auditActor(tn *tenant.Tenant, email string, n int) {
	ev.t.Helper()
	for range n {
		if _, err := ev.db.AuditEvents().AppendScoped(context.Background(), tn.ID, store.AuditEvent{
			ActorKind: store.ActorDepositor, Actor: email, IP: clientIP, Action: "transfer.created",
			ObjectKind: "transfer", ObjectID: id.New(id.Transfer),
		}); err != nil {
			ev.t.Fatal(err)
		}
	}
}

// auditEvents returns the audit events of tenant tid with action ("" for
// all).
func (ev *env) auditEvents(tid tenant.ID, action audit.Action) []store.AuditEvent {
	ev.t.Helper()
	page, err := ev.db.AuditEvents().List(context.Background(), store.AuditFilter{
		TenantID: tid, Action: string(action), Limit: store.MaxPageSize,
	})
	if err != nil {
		ev.t.Fatal(err)
	}
	return page.Items
}

// search runs Search as the super admin and fails on error.
func (ev *env) search(tn *tenant.Tenant, email string) Summary {
	ev.t.Helper()
	sum, err := ev.svc.Search(context.Background(), ev.super, clientIP, tn.ID, email)
	if err != nil {
		ev.t.Fatalf("Search: %v", err)
	}
	return sum
}

// erase runs Erase as the super admin and fails on error.
func (ev *env) erase(tn *tenant.Tenant, email string) EraseReport {
	ev.t.Helper()
	rep, err := ev.svc.Erase(context.Background(), ev.super, clientIP, tn.ID, email)
	if err != nil {
		ev.t.Fatalf("Erase: %v\nlogs:\n%s", err, ev.logs.String())
	}
	return rep
}

// transferExists reports whether the transfer trfID of tn has a row.
func (ev *env) transferExists(tn *tenant.Tenant, trfID string) bool {
	ev.t.Helper()
	_, err := ev.db.Transfers().Get(context.Background(), tn.ID, trfID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		ev.t.Fatal(err)
	}
	return err == nil
}

// principal returns an authenticated principal.
func principal(role store.AdminRole, username string, tids ...tenant.ID) adminauth.Principal {
	return adminauth.Principal{
		SessionID: id.New(id.AdminSession), State: store.SessionAuthenticated,
		Admin: adminauth.Account{ID: id.New(id.Admin), Username: username, Role: role, TenantIDs: tids},
	}
}

// wantErr fails unless errors.Is(err, target).
func wantErr(t *testing.T, what string, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("%s: got %v, want %v", what, err, target)
	}
}
