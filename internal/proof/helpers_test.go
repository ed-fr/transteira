package proof

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
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
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
)

// The tests that run on every engine are not parallel inside an engine:
// each PostgreSQL engine holds its own connection pool.

// Fixed values of the tests. Domains are fictitious.
const (
	hostA     = "transfer.entity-a.example.com"
	hostB     = "transfer.entity-b.example.com"
	alice     = "Alice@Entity-A.example.com" // sender of tenant A, as typed
	aliceNorm = "alice@entity-a.example.com"
	bob       = "bob@entity-a.example.com"
	carol     = "carol@customer.example.net"
	dave      = "dave@customer.example.net"
	sumA      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sumB      = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

var (
	testStart = time.Date(2026, 11, 5, 9, 30, 0, 0, time.UTC)
	clientIP  = netip.MustParseAddr("203.0.113.7")
	errBoom   = errors.New("injected fault")
)

// fakeClock is a settable clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// syncBuffer is a bytes.Buffer safe for concurrent use.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// env is a migrated database with tenants A and B, a signer and a service.
type env struct {
	t      testing.TB
	db     *store.DB
	clock  *fakeClock
	vault  *masterkey.Vault
	rec    *audit.Writer
	signer *Signer
	svc    *Service
	logs   *syncBuffer
	seclog *syncBuffer
	a, b   *tenant.Tenant
}

// newEnv builds an env on engine e; opts configure its service.
func newEnv(t testing.TB, e storetest.Engine, opts ...Option) *env {
	t.Helper()
	ctx := t.Context()
	clock := &fakeClock{now: testStart}
	db, err := store.Open(ctx, e.Config(), store.WithClock(clock.Now))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	kr, err := masterkey.New(masterkeytest.Key(t, "proof"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ev := &env{t: t, db: db, clock: clock, vault: masterkey.NewVault(db, kr, nil), rec: audit.New(db), logs: &syncBuffer{}, seclog: &syncBuffer{}}
	logger := slog.New(slog.NewTextHandler(ev.logs, nil))
	ev.signer = NewSigner(db, ev.vault, ev.rec, clock.Now, logger)
	opts = append([]Option{WithSecurityLog(securitylog.New(ev.seclog))}, opts...)
	ev.svc = NewService(db, ev.signer, ev.rec, clock.Now, logger, opts...)
	ev.a = ev.newTenant(hostA, "Entity A", "en")
	ev.b = ev.newTenant(hostB, "Entity B", "fr")
	return ev
}

// newTenant creates a tenant directly in the store.
func (ev *env) newTenant(fqdn, name, lang string) *tenant.Tenant {
	ev.t.Helper()
	tn, err := ev.db.Tenants().Create(ev.t.Context(), &tenant.Tenant{
		SetupState: tenant.SetupStateActive,
		Name:       name, FQDN: fqdn, DefaultLanguage: lang, MaxTransferBytes: 10 << 30, StorageQuotaBytes: 100 << 30,
	})
	if err != nil {
		ev.t.Fatalf("Create(%s): %v", fqdn, err)
	}
	return tn
}

// tx runs fn in a write transaction of tn.
func (ev *env) tx(tn *tenant.Tenant, fn func(tx *store.ScopedTx) error) error {
	sc, err := ev.db.Scoped(tn.ID)
	if err != nil {
		ev.t.Fatal(err)
	}
	return sc.Tx(ev.t.Context(), fn)
}

// prepare returns a sealer of the env's signer.
func (ev *env) prepare() *Sealer {
	ev.t.Helper()
	s, err := ev.signer.Prepare(ev.t.Context())
	if err != nil {
		ev.t.Fatalf("Prepare: %v", err)
	}
	return s
}

// seedOptions shape a seeded transfer.
type seedOptions struct {
	sender       string
	perRecipient bool
	level        bool
	// noDeposit leaves the transfer scanning, without deposit proof.
	scanning bool
	// noProof makes the transfer available without its deposit proof.
	noProof bool
}

// seeded is a seeded transfer.
type seeded struct {
	id    string
	links []store.RecipientLink
}

// tokenHash returns the SHA-256 of a token.
func tokenHash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// seed stores a transfer of tn to carol and dave with two files (one in a
// folder, too large to be scanned), finalized at the clock time and made
// available one minute later with its deposit proof, in the same
// transaction.
func (ev *env) seed(tn *tenant.Tenant, o seedOptions) seeded {
	ev.t.Helper()
	ctx := ev.t.Context()
	if o.sender == "" {
		o.sender = alice
	}
	trfID := id.New(id.Transfer)
	var files []store.TransferFile
	err := ev.tx(tn, func(tx *store.ScopedTx) error {
		now := ev.clock.Now()
		for i, f := range []struct {
			name, path, sum string
			size            int64
		}{{"plans.pdf", "", sumA, 1000}, {"vidéo (1).mp4", "docs/2026", sumB, 3_000_000_000}} {
			wk, _, err := ev.vault.NewDEKTx(ctx, tx)
			if err != nil {
				return err
			}
			upl, err := id.NewUploadToken()
			if err != nil {
				return err
			}
			files = append(files, store.TransferFile{
				ID: id.New(id.File), Name: f.name, Path: f.path, Size: f.size, DEKKeyID: wk, StorageName: storage.NewName(),
				UploadID: upl, SHA256: f.sum, CiphertextSize: f.size + 100, UploadedAt: now, Position: i,
			})
		}
		tr := store.Transfer{
			ID: trfID, SenderEmail: o.sender, SenderKind: store.DepositorInternal, ExpiryDays: 7, Language: "fr",
			LinkMode: store.LinkModeShared,
		}
		if o.perRecipient {
			tr.LinkMode = store.LinkModePerRecipient
		}
		if o.level {
			tr.ConfidentialityLevel, tr.Rules = "secret", &store.ConfidentialityRules{ExpiryDaysMask: 7}
			tr.ConfidentialityLabel = map[string]string{"fr": "Secret", "en": "Secret"}
		}
		trs := ev.db.Transfers()
		if err := trs.CreateTx(ctx, tx, tr, []string{carol, dave}, files); err != nil {
			return err
		}
		return trs.FinalizeTx(ctx, tx, trfID, now)
	})
	if err != nil {
		ev.t.Fatalf("seed: %v", err)
	}
	if o.scanning {
		return seeded{id: trfID}
	}
	ev.clock.Advance(time.Minute)
	sealer := ev.prepare()
	var links []store.RecipientLink
	err = ev.tx(tn, func(tx *store.ScopedTx) error {
		now := ev.clock.Now()
		for i, st := range []store.ScanStatus{store.ScanClean, store.ScanNotScannedTooLarge} {
			if err := ev.db.TransferFiles().SetScanResultTx(ctx, tx, files[i].ID, st, "", now); err != nil {
				return err
			}
		}
		n := 1
		if o.perRecipient {
			n = 2
		}
		tokens := make([]store.LinkToken, n)
		for i := range tokens {
			raw, err := id.NewDownloadToken()
			if err != nil {
				return err
			}
			wk, err := ev.vault.SealTx(ctx, tx, crypto.PurposeSecret, []byte(raw))
			if err != nil {
				return err
			}
			tokens[i] = store.LinkToken{Hash: tokenHash(raw), KeyID: wk}
		}
		var err error
		if o.perRecipient {
			links, err = ev.db.Transfers().MarkAvailableLinksTx(ctx, tx, trfID, tokens, now)
		} else {
			err = ev.db.Transfers().MarkAvailableTx(ctx, tx, trfID, tokens[0].Hash, tokens[0].KeyID, now)
		}
		if err != nil || o.noProof {
			return err
		}
		return sealer.DepositTx(ctx, tx, tn, trfID, now)
	})
	if err != nil {
		ev.t.Fatalf("seed available: %v", err)
	}
	return seeded{id: trfID, links: links}
}

// download records a complete download of trf at the clock time, through
// the recipient link linkID ("" for the shared link), with the proofs, as
// the download service does.
func (ev *env) download(tn *tenant.Tenant, trfID, linkID string) {
	ev.t.Helper()
	ctx := ev.t.Context()
	sealer := ev.prepare()
	err := ev.tx(tn, func(tx *store.ScopedTx) error {
		now := ev.clock.Now()
		linkFirst := false
		if linkID != "" {
			if err := ev.db.RecipientLinks().ClaimTx(ctx, tx, linkID, "", now); err != nil {
				return err
			}
			c, err := ev.db.RecipientLinks().CompleteTx(ctx, tx, linkID, now)
			if err != nil {
				return err
			}
			linkFirst = c.First
		}
		first, err := ev.db.Transfers().MarkFirstDownloadTx(ctx, tx, trfID, now, time.Time{})
		if err != nil {
			return err
		}
		if linkFirst {
			if err := sealer.RecipientDeliveryTx(ctx, tx, tn, trfID, linkID, now); err != nil {
				return err
			}
		}
		if first {
			return sealer.OverallDeliveryTx(ctx, tx, tn, trfID, now)
		}
		return nil
	})
	if err != nil {
		ev.t.Fatalf("download: %v", err)
	}
}

// end destroys the keys of trf and moves it to status deleted.
func (ev *env) end(tn *tenant.Tenant, trfID string) {
	ev.t.Helper()
	ctx := ev.t.Context()
	err := ev.tx(tn, func(tx *store.ScopedTx) error {
		d, err := ev.db.Transfers().GetTx(ctx, tx, trfID)
		if err != nil {
			return err
		}
		if _, err := ev.db.RecipientLinks().DestroyKeysTx(ctx, tx, trfID); err != nil {
			return err
		}
		keys := []string{d.DownloadTokenKeyID}
		for _, f := range d.Files {
			keys = append(keys, f.DEKKeyID)
		}
		for _, k := range keys {
			if k == "" {
				continue
			}
			if err := ev.db.WrappedKeys().DeleteTx(ctx, tx, k); err != nil {
				return err
			}
		}
		return ev.db.Transfers().SetStatusTx(ctx, tx, trfID, d.Status, store.TransferDeleted, ev.clock.Now())
	})
	if err != nil {
		ev.t.Fatalf("end: %v", err)
	}
}

// proofRow reads a stored proof.
func (ev *env) proofRow(tn *tenant.Tenant, trfID string, kind store.ProofKind, linkID string) store.TransferProof {
	ev.t.Helper()
	p, err := ev.db.TransferProofs().Get(ev.t.Context(), tn.ID, trfID, kind, linkID)
	if err != nil {
		ev.t.Fatalf("Get proof(%s %s %s): %v", trfID, kind, linkID, err)
	}
	return p
}

// keys returns the published keys.
func (ev *env) keys() []PublicKey {
	ev.t.Helper()
	k, err := ev.signer.Keys(ev.t.Context())
	if err != nil {
		ev.t.Fatal(err)
	}
	return k
}

// auditEvents returns the audit events of tid ("" for every event) with
// action.
func (ev *env) auditEvents(tid tenant.ID, action audit.Action) []store.AuditEvent {
	ev.t.Helper()
	page, err := ev.db.AuditEvents().List(ev.t.Context(), store.AuditFilter{TenantID: tid, Action: string(action), Limit: store.MaxPageSize})
	if err != nil {
		ev.t.Fatal(err)
	}
	return page.Items
}

// principal returns an authenticated session of an administrator of role
// role attached to tids.
func principal(role store.AdminRole, tids ...tenant.ID) adminauth.Principal {
	return adminauth.Principal{
		SessionID: "as_test", State: store.SessionAuthenticated,
		Admin: adminauth.Account{ID: id.New(id.Admin), Username: "admin-" + strings.ReplaceAll(string(role), "_", "-"), Role: role, TenantIDs: tids},
	}
}

// faultVault wraps a vault and injects faults.
type faultVault struct {
	Vault
	wrapErr    error
	openErr    error
	openSeed   []byte
	beforeWrap func()
}

func (v *faultVault) WrapSystem(p crypto.Purpose, plaintext []byte) (store.SystemSecret, error) {
	if v.beforeWrap != nil {
		v.beforeWrap()
	}
	if v.wrapErr != nil {
		return store.SystemSecret{}, v.wrapErr
	}
	return v.Vault.WrapSystem(p, plaintext)
}

func (v *faultVault) OpenSystem(ctx context.Context, p crypto.Purpose, secretID string) ([]byte, error) {
	if v.openErr != nil {
		return nil, v.openErr
	}
	if v.openSeed != nil {
		return bytes.Clone(v.openSeed), nil
	}
	return v.Vault.OpenSystem(ctx, p, secretID)
}

// faultAudit fails every audit write.
type faultAudit struct{}

func (faultAudit) RecordTx(context.Context, *store.SystemTx, audit.Event) error { return errBoom }
func (faultAudit) RecordScoped(context.Context, tenant.ID, audit.Event) error   { return errBoom }

// failingReader fails every read.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errBoom }

// failingLog fails every security log write.
type failingLog struct{}

func (failingLog) Log(securitylog.Event) error { return errBoom }
