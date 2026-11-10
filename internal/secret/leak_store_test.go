package secret

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/tte2"
)

// browserSecret is a secret sealed as the web app does, with every value
// that must never be stored, logged or audited.
type browserSecret struct {
	key        []byte // K, from the fragment of the link
	fragment   string // K encoded in the fragment
	passphrase string
	keyProof   []byte
	proof      []byte
	req        CreateRequest
}

// sealBrowser seals text under a new key K and passphrase pass (none when
// ""), as the web app does, and returns the creation request.
func sealBrowser(t *testing.T, text, pass string) browserSecret {
	t.Helper()
	key, err := tte2.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	fragment, err := tte2.EncodeKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var d tte2.PassphraseDescriptor
	if pass != "" {
		if d, err = tte2.NewPassphraseDescriptor(); err != nil {
			t.Fatal(err)
		}
	}
	root, err := tte2.DeriveSecretKey(key, pass, d)
	if err != nil {
		t.Fatal(err)
	}
	sealedText, err := tte2.SealSecret(root, text)
	if err != nil {
		t.Fatal(err)
	}
	kp, _ := tte2.SecretKeyProof(key)
	p, _ := tte2.SecretProof(root)
	b := browserSecret{key: key, fragment: fragment, passphrase: pass, keyProof: kp, proof: p}
	b.req = CreateRequest{
		EncryptedText: sealedText, Verifier: tte2.EncodeProof(tte2.SecretVerifier(p)),
		KeyVerifier: tte2.EncodeProof(tte2.SecretVerifier(kp)), ExpiresIn: "1d", Delivery: DeliveryLink,
	}
	if pass != "" {
		b.req.Passphrase = &Passphrase{KDF: d.KDF, Iterations: d.Iterations, Salt: d.EncodedSalt()}
	}
	return b
}

// TestNoSecretMaterialInLogs runs the full flow of an e-mail secret with a
// passphrase and a file (creation, file upload, e-mail send, wrong proofs,
// unknown link, reveal, file download) and of a link secret, on the real
// store, audit writer, security log and file storage, on every engine
// (threat model T-375). The application log (debug level), the security
// log, every audit row and every table must then hold none of the link
// tokens, the fragment key, the passphrase, the proofs (right or wrong),
// the file grant or the plaintext; once the secrets ended, the database no
// longer holds their verifiers nor their sealed text either.
func TestNoSecretMaterialInLogs(t *testing.T) {
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
		tn, err := db.Tenants().Create(ctx, &tenant.Tenant{
			SetupState: tenant.SetupStateActive, Name: "Entity A", FQDN: "transfer.entity-a.example.com",
			DefaultLanguage: "en", MaxTransferBytes: 1 << 30, StorageQuotaBytes: 1 << 40,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.SMTPSettings().Put(ctx, tn.ID, store.SMTPConfig{
			Host: "smtp-relay", Port: 25, Security: store.SMTPSecurityNone, FromAddress: "noreply@entity-a.example.com",
		}); err != nil {
			t.Fatal(err)
		}
		files, err := storage.New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = files.Close() })
		appLog, secLog := &lockedBuffer{}, &lockedBuffer{}
		logger := slog.New(slog.NewTextHandler(appLog, &slog.HandlerOptions{Level: slog.LevelDebug}))
		mailer := &fakeMailer{}
		svc, err := New(Deps{
			Secrets: db.Secrets(vault), Creators: &fakeCreators{}, Scrubber: vault, Files: files,
			SecurityLog: securitylog.New(secLog), Directory: StoreDirectory{DB: db},
			Notifier: notify.New(vault, db.SMTPSettings(), nil, notify.Options{Logger: logger, Now: func() time.Time { return now }}),
			Mailer:   mailer,
		}, Options{Audit: audit.New(db), Now: func() time.Time { return now }, Logger: logger})
		if err != nil {
			t.Fatal(err)
		}
		ip := netip.MustParseAddr("203.0.113.7")

		// The file, sealed in the browser under K.
		mailed := sealBrowser(t, "the launch codes", "correct horse battery staple")
		var stream bytes.Buffer
		w, _ := tte2.NewWriter(&stream, mailed.key, 0)
		_, _ = w.Write(bytes.Repeat([]byte("plain file bytes "), 4000))
		_ = w.Close()
		req := mailed.req
		req.Delivery, req.Recipient, req.ReadReceipt = DeliveryEmail, ptr(carol), true
		req.File = &File{Size: int64(stream.Len()), EncryptedMetadata: "AQ" + strings.Repeat("A", 38)}
		created, err := svc.Create(ctx, tn, internalSender(), req)
		if err != nil || created.State != store.SecretPending {
			t.Fatalf("create = %+v, %v", created, err)
		}
		if _, err := svc.UploadFile(ctx, tn, internalSender(), created.ID, bytes.NewReader(stream.Bytes())); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Send(ctx, tn, internalSender(), created.ID, created.Token, mailed.fragment); err != nil {
			t.Fatal(err)
		}
		if len(mailer.sent) != 1 || !strings.Contains(mailer.sent[0].Message.Text, created.Token+"#k="+mailed.fragment) {
			t.Fatal("the link mail is missing")
		}

		// Failures written to the security log: an unknown link, a wrong
		// key proof (truncated link) and a wrong passphrase.
		unknown, _ := id.NewSecretToken()
		if _, err := svc.Status(ctx, tn, ip, unknown); err == nil {
			t.Fatal("unknown token accepted")
		}
		wrongKey, wrongProof := bytes.Clone(mailed.keyProof), bytes.Clone(mailed.proof)
		wrongKey[0] ^= 1
		wrongProof[0] ^= 1
		if _, err := svc.Reveal(ctx, tn, ip, created.Token, tte2.EncodeProof(wrongKey), tte2.EncodeProof(mailed.proof)); err == nil {
			t.Fatal("wrong key proof accepted")
		}
		if _, err := svc.Reveal(ctx, tn, ip, created.Token, tte2.EncodeProof(mailed.keyProof), tte2.EncodeProof(wrongProof)); err == nil {
			t.Fatal("wrong proof accepted")
		}

		// The reveal, then the file download.
		if _, err := svc.Status(ctx, tn, ip, created.Token); err != nil {
			t.Fatal(err)
		}
		out, err := svc.Reveal(ctx, tn, ip, created.Token, tte2.EncodeProof(mailed.keyProof), tte2.EncodeProof(mailed.proof))
		if err != nil || out.FileGrant == "" {
			t.Fatalf("reveal = %+v, %v", out, err)
		}
		d, err := svc.DownloadFile(ctx, tn, ip, created.Token, out.FileGrant)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := io.ReadAll(d); err != nil || !bytes.Equal(got, stream.Bytes()) {
			t.Fatalf("download: %d bytes, %v", len(got), err)
		}
		_ = d.Close()
		d.Delivered(ctx)

		// A link secret without passphrase, read at once.
		linked := sealBrowser(t, "the wifi password", "")
		lc, err := svc.Create(ctx, tn, internalSender(), linked.req)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Reveal(ctx, tn, ip, lc.Token, tte2.EncodeProof(linked.keyProof), tte2.EncodeProof(linked.proof)); err != nil {
			t.Fatal(err)
		}

		// The flow left its traces: audit rows and security events.
		page, err := db.AuditEvents().List(ctx, store.AuditFilter{TenantID: tn.ID, Limit: store.MaxPageSize})
		if err != nil {
			t.Fatal(err)
		}
		auditRows := fmt.Sprintf("%+v", page.Items)
		for _, action := range []audit.Action{
			audit.ActionSecretCreated, audit.ActionSecretSent, audit.ActionSecretRevealed, audit.ActionSecretFileDownloaded,
		} {
			if !strings.Contains(auditRows, string(action)) {
				t.Errorf("audit misses %s: %s", action, auditRows)
			}
		}
		for _, ev := range []string{"secret_invalid", "secret_proof_invalid"} {
			if !strings.Contains(secLog.String(), ev) {
				t.Errorf("security log misses %s: %s", ev, secLog.String())
			}
		}
		if !strings.Contains(auditRows, created.ID) || !strings.Contains(secLog.String(), "203.0.113.7") {
			t.Fatal("the haystacks miss the identifiers they should hold")
		}

		// The needles, as strings and as raw bytes where they are bytes.
		type needle struct {
			name string
			v    []byte
		}
		var needles []needle
		add := func(name string, raw []byte) {
			needles = append(needles,
				needle{name, raw},
				needle{name + " (base64url)", []byte(base64.RawURLEncoding.EncodeToString(raw))},
				needle{name + " (hex)", fmt.Appendf(nil, "%x", raw)},
			)
		}
		for _, s := range []struct {
			name string
			b    browserSecret
			tok  string
		}{{"mailed", mailed, created.Token}, {"linked", linked, lc.Token}} {
			needles = append(needles, needle{s.name + " token", []byte(s.tok)}, needle{s.name + " fragment", []byte(s.b.fragment)})
			add(s.name+" key", s.b.key)
			add(s.name+" key proof", s.b.keyProof)
			add(s.name+" proof", s.b.proof)
		}
		add("wrong key proof", wrongKey)
		add("wrong proof", wrongProof)
		needles = append(needles,
			needle{"unknown token", []byte(unknown)},
			needle{"passphrase", []byte(mailed.passphrase)},
			needle{"file grant", []byte(out.FileGrant)},
			needle{"mailed plaintext", []byte("the launch codes")},
			needle{"linked plaintext", []byte("the wifi password")},
			needle{"file plaintext", []byte("plain file bytes")},
		)
		// Ended secrets: no verifier and no sealed text left in the
		// database (the tombstones are empty).
		ended := []needle{
			{"mailed verifier", []byte(mailed.req.Verifier)},
			{"mailed key verifier", []byte(mailed.req.KeyVerifier)},
			{"linked verifier", []byte(linked.req.Verifier)},
			{"mailed sealed text", []byte(mailed.req.EncryptedText)},
			{"linked sealed text", []byte(linked.req.EncryptedText)},
		}
		for _, v := range [][]byte{tte2.SecretVerifier(mailed.proof), tte2.SecretVerifier(mailed.keyProof), tte2.SecretVerifier(linked.proof)} {
			ended = append(ended, needle{"raw verifier", v})
		}

		dump := dumpTables(t, e)
		if !bytes.Contains(dump, []byte(created.ID)) || !bytes.Contains(dump, []byte(lc.ID)) {
			t.Fatal("the dump misses the secrets")
		}
		haystacks := map[string][]byte{
			"application log": []byte(appLog.String()),
			"security log":    []byte(secLog.String()),
			"audit rows":      []byte(auditRows),
			"database":        dump,
		}
		for hay, content := range haystacks {
			for _, n := range needles {
				if len(n.v) > 0 && bytes.Contains(content, n.v) {
					t.Errorf("the %s holds the %s", hay, n.name)
				}
			}
			for _, n := range ended {
				if bytes.Contains(content, n.v) {
					t.Errorf("the %s holds the %s of an ended secret", hay, n.name)
				}
			}
		}
	})
}
