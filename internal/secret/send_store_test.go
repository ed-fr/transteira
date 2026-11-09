package secret

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/transfer"
	"github.com/ed-fr/transteira/internal/tte2"
)

// lockedBuffer is a bytes.Buffer safe for concurrent writes (the log
// handler).
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// dumpTables returns the content of every table of the database of e, read
// outside the store (on PostgreSQL with the owner role in the system scope,
// so that the row-level security hides nothing).
func dumpTables(t *testing.T, e storetest.Engine) []byte {
	t.Helper()
	ctx := context.Background()
	driver, dsn, list := "sqlite", e.DSN, `SELECT name FROM sqlite_master WHERE type = 'table'`
	if e.Driver == "postgres" {
		driver, dsn = "pgx", e.MigrateDSN
		list = `SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'`
	}
	raw, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	tx, err := raw.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if e.Driver == "postgres" {
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.system_scope', 'on', true)`); err != nil {
			t.Fatal(err)
		}
	}
	var tables []string
	rows, err := tx.QueryContext(ctx, list)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	_ = rows.Close()
	if len(tables) < 10 {
		t.Fatalf("only %d tables found", len(tables))
	}
	var out bytes.Buffer
	for _, table := range tables {
		rows, err := tx.QueryContext(ctx, `SELECT * FROM "`+table+`"`)
		if err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		cols, _ := rows.Columns()
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		for rows.Next() {
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatalf("%s: %v", table, err)
			}
			for _, v := range vals {
				switch v := v.(type) {
				case []byte:
					out.Write(v)
				default:
					fmt.Fprint(&out, v)
				}
				out.WriteByte(0)
			}
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		_ = rows.Close()
	}
	return out.Bytes()
}

// TestSendWithStore runs the e-mail delivery on the real store and the
// real notifier, on every engine: the recipient rules at the creation, the
// token check and the single activation of the send call, the link of the
// mail, the read receipts (read, expired unread, never after a deletion),
// the recipient forced to the inviter of an external, and that neither the
// token nor the key is left in any table, log or audit event (T-363).
func TestSendWithStore(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		now := time.Now().UTC().Truncate(time.Millisecond)
		db, err := store.Open(ctx, e.Config(), store.WithClock(func() time.Time { return now }))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		kr, err := masterkey.New(masterkeytest.Key(t, "secret"), nil)
		if err != nil {
			t.Fatal(err)
		}
		vault := masterkey.NewVault(db, kr, nil)
		newTenant := func(fqdn string) *tenant.Tenant {
			tn, err := db.Tenants().Create(ctx, &tenant.Tenant{
				SetupState: tenant.SetupStateActive, Name: fqdn, FQDN: fqdn, DefaultLanguage: "en",
				MaxTransferBytes: 1 << 30, StorageQuotaBytes: 1 << 40,
			})
			if err != nil {
				t.Fatal(err)
			}
			return tn
		}
		a, b := newTenant("transfer.entity-a.example.com"), newTenant("transfer.entity-b.example.com")
		if err := db.SMTPSettings().Put(ctx, a.ID, store.SMTPConfig{
			Host: "smtp-relay", Port: 25, Security: store.SMTPSecurityNone, FromAddress: "noreply@entity-a.example.com",
		}); err != nil {
			t.Fatal(err)
		}
		logs := &lockedBuffer{}
		logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		mailer, seclog, rec := &fakeMailer{}, &fakeSeclog{}, &fakeAudit{}
		svc, err := New(Deps{
			Secrets: db.Secrets(vault), Creators: &fakeCreators{}, Scrubber: vault, Files: &fakeFiles{}, SecurityLog: seclog,
			Directory: StoreDirectory{DB: db}, Notifier: notify.New(vault, db.SMTPSettings(), nil, notify.Options{
				Logger: logger, Now: func() time.Time { return now },
			}), Mailer: mailer,
		}, Options{Audit: rec, Now: func() time.Time { return now }, Logger: logger})
		if err != nil {
			t.Fatal(err)
		}

		// The recipient rules of the tenant apply at the creation.
		if _, err := db.Blocklist().Create(ctx, a.ID, store.BlocklistEntry{
			Kind: store.BlockDomain, Value: "blocked.example.org", CreatedBy: "admin",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.RecipientRules().Replace(ctx, a.ID, store.RecipientRuleSet{Denied: []string{"denied.example.org"}}, now); err != nil {
			t.Fatal(err)
		}
		s, _ := seal(t, "the plans", "")
		for _, rcpt := range []string{"x@blocked.example.org", "x@sub.denied.example.org"} {
			if _, err := svc.Create(ctx, a, internalSender(), emailRequest(s, rcpt)); !errors.Is(err, ErrRecipientRefused) {
				t.Errorf("%s: %v", rcpt, err)
			}
		}

		// Created pending, then sent with its token and key.
		req := emailRequest(s, carol)
		req.ReadReceipt = true
		created, err := svc.Create(ctx, a, internalSender(), req)
		if err != nil || created.State != store.SecretPending {
			t.Fatalf("create = %+v, %v", created, err)
		}
		_, key := linkHalves(t)
		other, _ := id.NewSecretToken()
		if _, err := svc.Send(ctx, a, internalSender(), created.ID, other, key); !errors.Is(err, ErrNotFound) {
			t.Errorf("send with another token: %v", err)
		}
		if _, err := svc.Send(ctx, b, internalSender(), created.ID, created.Token, key); !errors.Is(err, ErrNotFound) {
			t.Errorf("send under another tenant: %v", err)
		}
		if len(mailer.sent) != 0 {
			t.Fatal("a refused send queued a mail")
		}
		sent, err := svc.Send(ctx, a, internalSender(), created.ID, created.Token, key)
		if err != nil || sent.State != store.SecretActive || !sent.ExpiresAt.Equal(now.Add(24*time.Hour)) {
			t.Fatalf("send = %+v, %v", sent, err)
		}
		if _, err := svc.Send(ctx, a, internalSender(), created.ID, created.Token, key); !errors.Is(err, ErrConflict) {
			t.Errorf("second send: %v", err)
		}
		if len(mailer.sent) != 1 {
			t.Fatalf("%d mails", len(mailer.sent))
		}
		msg := mailer.sent[0].Message
		link := "https://transfer.entity-a.example.com/s/" + created.Token + "#k=" + key
		if len(msg.To) != 1 || msg.To[0] != carol || !strings.Contains(msg.Text, link) || !strings.Contains(msg.HTML, link) {
			t.Errorf("mail to %v, link in the text %v", msg.To, strings.Contains(msg.Text, link))
		}

		// T-363: neither the token nor the key (nor its bytes) is stored,
		// logged nor audited.
		keyBytes, _ := tte2.DecodeKey(key)
		dump := dumpTables(t, e)
		for name, x := range map[string][]byte{"token": []byte(created.Token), "key": []byte(key), "key bytes": keyBytes} {
			if bytes.Contains(dump, x) {
				t.Errorf("the %s is in the database", name)
			}
			if strings.Contains(logs.String(), string(x)) {
				t.Errorf("the %s is in the logs", name)
			}
			if strings.Contains(fmt.Sprintf("%+v %+v", rec.events, seclog.events), string(x)) {
				t.Errorf("the %s is in the audit or the security log", name)
			}
		}
		if !bytes.Contains(dump, []byte(created.ID)) {
			t.Fatal("the dump misses the secret")
		}

		// The reveal sends the read receipt to the creator, once.
		if _, err := svc.Reveal(ctx, a, internalIP, created.Token, s.keyProof, s.proof); err != nil {
			t.Fatal(err)
		}
		if got := mailer.templates(); len(got) != 2 || got[1] != mail.TemplateSecretReceipt || mailer.sent[1].Message.To[0] != alice {
			t.Fatalf("mails = %v", got)
		}
		read, _ := db.Secrets(vault).Get(ctx, a.ID, created.ID)
		svc.receipt(ctx, a, read, mail.SecretOutcomeRead, now)
		if len(mailer.sent) != 2 {
			t.Error("a second receipt was sent")
		}

		// Expired unread: the receipt of the lifecycle task. A deleted
		// secret never gets one.
		send := func() (Created, store.Secret) {
			c, err := svc.Create(ctx, a, internalSender(), req)
			if err != nil {
				t.Fatal(err)
			}
			_, k := linkHalves(t)
			sec, err := svc.Send(ctx, a, internalSender(), c.ID, c.Token, k)
			if err != nil {
				t.Fatal(err)
			}
			return c, sec
		}
		_, expiring := send()
		deletedC, _ := send()
		if err := svc.DeleteMine(ctx, a, alice, internalIP, deletedC.ID); err != nil {
			t.Fatal(err)
		}
		deleted, _ := db.Secrets(vault).Get(ctx, a.ID, deletedC.ID)
		svc.Expired(ctx, store.EndedSecret{Secret: deleted})
		ended, _, err := db.Secrets(vault).ExpireDue(ctx, now.Add(48*time.Hour), 10)
		if err != nil || len(ended) != 1 || ended[0].Secret.ID != expiring.ID {
			t.Fatalf("expired = %+v, %v", ended, err)
		}
		before := len(mailer.sent)
		svc.Expired(ctx, ended[0])
		svc.Expired(ctx, ended[0])
		if got := mailer.templates(); len(got) != before+1 || got[before] != mail.TemplateSecretReceipt {
			t.Errorf("mails after the expiry = %v", got)
		}

		// An invited external mails its inviter, whatever recipient it
		// names.
		inv := id.New(id.Invitation)
		hash := id.HashToken(inv)
		if err := db.Invitations().Create(ctx, a.ID, store.Invitation{
			ID: inv, TokenHash: hash, Email: bob, InvitedBy: alice, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		external := transfer.Sender{Depositor: store.Depositor{Email: bob, Kind: store.DepositorExternal, InvitationID: inv}}
		ext, err := svc.Create(ctx, a, external, emailRequest(s, carol))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := db.Secrets(vault).Get(ctx, a.ID, ext.ID)
		if got.RecipientEmail != alice || got.CreatorKind != store.SecretCreatorExternal {
			t.Errorf("external secret = %+v", got)
		}
	})
}
