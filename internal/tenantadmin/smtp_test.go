package tenantadmin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/netpolicy"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// relay is valid settings of an unauthenticated relay.
func relay() SMTPUpdate {
	return SMTPUpdate{Host: "smtp-relay", Port: 25, Security: store.SMTPSecurityNone, FromAddress: "noreply@entity-a.example.com"}
}

// authenticated is valid settings of an authenticated server.
func authenticated(pw string) SMTPUpdate {
	return SMTPUpdate{
		Host: "smtp.example.com", Port: 587, Security: store.SMTPSecuritySTARTTLS, Username: "mailer",
		Password: &pw, FromAddress: "Transfer@Entity-A.example.com", FromName: "Entity A",
	}
}

func TestSMTPSettings(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		_, err := ev.svc.GetSMTP(ctx, ev.adminA, ev.a.ID)
		wantErr(t, "none yet", err, ErrNotFound)

		v, err := ev.svc.UpdateSMTP(ctx, ev.adminA, ev.a.ID, authenticated("s3cr3t-pw"), clientIP)
		mustNoErr(t, "put", err)
		if !v.PasswordSet || v.Username != "mailer" || v.FromAddress != "transfer@entity-a.example.com" {
			t.Fatalf("view: %+v", v)
		}
		cfg, err := ev.db.SMTPSettings().Get(ctx, ev.a.ID)
		mustNoErr(t, "stored", err)
		pw, err := ev.vault.Open(ctx, ev.a.ID, crypto.PurposeSecret, cfg.PasswordKeyID)
		mustNoErr(t, "open", err)
		if string(pw) != "s3cr3t-pw" {
			t.Fatal("password not sealed as given")
		}
		firstKey := cfg.PasswordKeyID

		// Keeping the password while only the sender changes.
		in := authenticated("")
		in.Password, in.FromName = nil, "Entity A Transfer"
		v, err = ev.svc.UpdateSMTP(ctx, ev.adminA, ev.a.ID, in, clientIP)
		mustNoErr(t, "keep", err)
		if !v.PasswordSet {
			t.Fatal("password lost")
		}
		// Changing the host without the password is refused.
		in.Host = "evil.example.net"
		_, err = ev.svc.UpdateSMTP(ctx, ev.adminA, ev.a.ID, in, clientIP)
		wantInvalid(t, "host change keeps password", err, FieldPassword)

		// Replacing the password destroys the previous secret.
		v, err = ev.svc.UpdateSMTP(ctx, ev.adminA, ev.a.ID, authenticated("n3w-pw"), clientIP)
		mustNoErr(t, "replace", err)
		if _, err := ev.db.WrappedKeys().Get(ctx, ev.a.ID, firstKey); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("old secret kept: %v", err)
		}
		// Removing it.
		rm := relay()
		rm.RemovePassword = true
		v, err = ev.svc.UpdateSMTP(ctx, ev.adminA, ev.a.ID, rm, clientIP)
		mustNoErr(t, "remove", err)
		if v.PasswordSet || v.Username != "" {
			t.Fatalf("after removal: %+v", v)
		}
		ids, err := ev.db.WrappedKeys().ListIDs(ctx, ev.a.ID, "", 10)
		mustNoErr(t, "keys", err)
		if len(ids) != 0 {
			t.Fatalf("secrets left: %v", ids)
		}
		got, err := ev.svc.GetSMTP(ctx, ev.adminA, ev.a.ID)
		mustNoErr(t, "get", err)
		if got.Host != "smtp-relay" {
			t.Fatalf("get: %+v", got)
		}

		// Audit: never the password.
		evs := ev.auditEvents(t, ev.a.ID, ActionTenantSMTPUpdated)
		if len(evs) != 4 {
			t.Fatalf("%d events", len(evs))
		}
		for _, x := range evs {
			if strings.Contains(string(x.Details), "s3cr3t") || strings.Contains(string(x.Details), "n3w-pw") {
				t.Fatalf("secret in audit: %s", x.Details)
			}
		}
		var d struct {
			Fields      []string
			Credentials string
		}
		removed := false
		for _, x := range evs {
			mustNoErr(t, "details", json.Unmarshal(x.Details, &d))
			removed = removed || (d.Credentials == "removed" && len(d.Fields) > 0)
		}
		if !removed {
			t.Fatal("no removal event")
		}

		_, err = ev.svc.GetSMTP(ctx, ev.adminB, ev.a.ID)
		wantErr(t, "other tenant get", err, ErrNotFound)
		_, err = ev.svc.UpdateSMTP(ctx, ev.adminB, ev.a.ID, relay(), clientIP)
		wantErr(t, "other tenant put", err, ErrNotFound)
	})
}

func TestSMTPSettingsValidation(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	for name, tc := range map[string]struct {
		edit  func(*SMTPUpdate)
		field string
	}{
		"host":          {func(u *SMTPUpdate) { u.Host = "smtp relay" }, FieldHost},
		"empty host":    {func(u *SMTPUpdate) { u.Host = " " }, FieldHost},
		"denied ip":     {func(u *SMTPUpdate) { u.Host = "169.254.169.254" }, FieldHost},
		"denied v6":     {func(u *SMTPUpdate) { u.Host = "::1" }, FieldHost},
		"port":          {func(u *SMTPUpdate) { u.Port = 0 }, FieldPort},
		"security":      {func(u *SMTPUpdate) { u.Security = "ssl" }, FieldSecurity},
		"username":      {func(u *SMTPUpdate) { u.Username = "a\nb" }, FieldUsername},
		"clear auth":    {func(u *SMTPUpdate) { u.Username = "mailer" }, FieldUsername},
		"both":          {func(u *SMTPUpdate) { u.Password, u.RemovePassword = ptr("x"), true }, FieldPassword},
		"empty pw":      {func(u *SMTPUpdate) { u.Security, u.Username, u.Password = "tls", "m", ptr("") }, FieldPassword},
		"pw no user":    {func(u *SMTPUpdate) { u.Security, u.Password = "tls", ptr("x") }, FieldPassword},
		"from":          {func(u *SMTPUpdate) { u.FromAddress = "not an address" }, FieldFromAddress},
		"from name":     {func(u *SMTPUpdate) { u.FromName = "x\r\nBcc: y" }, FieldFromName},
		"long username": {func(u *SMTPUpdate) { u.Username = strings.Repeat("u", 321) }, FieldUsername},
	} {
		in := relay()
		tc.edit(&in)
		_, err := ev.svc.UpdateSMTP(ctx, ev.adminA, ev.a.ID, in, clientIP)
		wantInvalid(t, name, err, tc.field)
	}

	f := ev.faults("smtp")
	_, err := ev.svc.UpdateSMTP(ctx, ev.adminA, ev.a.ID, relay(), clientIP)
	wantErr(t, "read current", err, errBoom)
	_, err = ev.svc.GetSMTP(ctx, ev.adminA, ev.a.ID)
	wantErr(t, "get", err, errBoom)
	f.after["smtp"] = 1 // the read-back fails
	_, err = ev.svc.UpdateSMTP(ctx, ev.adminA, ev.a.ID, relay(), clientIP)
	wantErr(t, "read back", err, errBoom)

	f = ev.faults("putSMTP")
	_, err = ev.svc.UpdateSMTP(ctx, ev.adminA, ev.a.ID, relay(), clientIP)
	wantErr(t, "put", err, errBoom)
	f.errs["putSMTP"] = store.ErrInvalid
	_, err = ev.svc.UpdateSMTP(ctx, ev.adminA, ev.a.ID, relay(), clientIP)
	wantInvalid(t, "store invalid", err, "")
	f.errs["putSMTP"] = store.ErrNotFound
	_, err = ev.svc.UpdateSMTP(ctx, ev.adminA, ev.a.ID, relay(), clientIP)
	wantErr(t, "gone", err, ErrNotFound)
}

func TestStoreRepoPutSMTPFaults(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	r := newStoreRepo(ev.db, ev.vault, nil)
	cfg := store.SMTPConfig{Host: "h", Port: 25, Security: store.SMTPSecuritySTARTTLS, Username: "u", FromAddress: "a@example.com"}
	mustNoErr(t, "seed", r.putSMTP(ctx, ev.a.ID, cfg, passwordUpdate{password: []byte("pw")}))

	// Keeping the stored password is checked against the row read inside
	// the transaction: any change of host, port or username is refused.
	for name, edit := range map[string]func(*store.SMTPConfig){
		"host":     func(c *store.SMTPConfig) { c.Host = "other.example.com" },
		"port":     func(c *store.SMTPConfig) { c.Port = 587 },
		"username": func(c *store.SMTPConfig) { c.Username = "other" },
	} {
		next := cfg
		edit(&next)
		wantErr(t, "keep with new "+name, r.putSMTP(ctx, ev.a.ID, next, passwordUpdate{keep: true}), errPasswordRequired)
	}
	same := cfg
	same.FromName = "Entity A"
	mustNoErr(t, "keep same server", r.putSMTP(ctx, ev.a.ID, same, passwordUpdate{keep: true}))
	// A concurrent change between the service read and the transaction:
	// the transaction sees another host and refuses to keep the password.
	r.getSMTPTx = func(ctx context.Context, tx *store.ScopedTx) (store.SMTPConfig, error) {
		c, err := ev.db.SMTPSettings().GetTx(ctx, tx)
		c.Host = "moved.example.com"
		return c, err
	}
	wantErr(t, "concurrent change", r.putSMTP(ctx, ev.a.ID, cfg, passwordUpdate{keep: true}), errPasswordRequired)
	r = newStoreRepo(ev.db, ev.vault, nil)

	if err := r.putSMTP(ctx, "bad", cfg, passwordUpdate{}); err == nil {
		t.Error("malformed tenant accepted")
	}
	if _, err := r.usedBytes(ctx, "bad"); err == nil {
		t.Error("malformed tenant accepted")
	}
	r.getSMTPTx = func(context.Context, *store.ScopedTx) (store.SMTPConfig, error) { return store.SMTPConfig{}, errBoom }
	wantErr(t, "get", r.putSMTP(ctx, ev.a.ID, cfg, passwordUpdate{keep: true}), errBoom)
	r = newStoreRepo(ev.db, ev.vault, nil)
	r.sealTx = func(context.Context, *store.ScopedTx, []byte) (string, error) { return "", errBoom }
	wantErr(t, "seal", r.putSMTP(ctx, ev.a.ID, cfg, passwordUpdate{password: []byte("x")}), errBoom)
	r = newStoreRepo(ev.db, ev.vault, nil)
	r.deleteKeyTx = func(context.Context, *store.ScopedTx, string) error { return errBoom }
	wantErr(t, "delete old", r.putSMTP(ctx, ev.a.ID, cfg, passwordUpdate{password: []byte("x")}), errBoom)
	r = newStoreRepo(ev.db, ev.vault, nil)
	cfg.Host = "bad host"
	wantErr(t, "put", r.putSMTP(ctx, ev.a.ID, cfg, passwordUpdate{}), store.ErrInvalid)
	r.usedTx = func(context.Context, *store.ScopedTx) (int64, error) { return 0, errBoom }
	if _, err := r.usedBytes(ctx, ev.a.ID); !errors.Is(err, errBoom) {
		t.Errorf("used bytes: %v", err)
	}
}

func TestSMTPTest(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		_, err := ev.svc.TestSMTP(ctx, ev.adminA, ev.a.ID, "admin@entity-a.example.com", clientIP)
		wantErr(t, "no settings", err, ErrNotFound)

		_, err = ev.svc.UpdateSMTP(ctx, ev.adminA, ev.a.ID, authenticated("pa55word"), clientIP)
		mustNoErr(t, "settings", err)
		res, err := ev.svc.TestSMTP(ctx, ev.adminA, ev.a.ID, "Admin@Entity-A.example.com", clientIP)
		mustNoErr(t, "test", err)
		if !res.Success || res.Stage != StageDone || res.Error != "" {
			t.Fatalf("result: %+v", res)
		}
		sent := ev.mailer.sent[0]
		if sent.settings.Password != "pa55word" || sent.msg.To[0] != "Admin@entity-a.example.com" ||
			!strings.Contains(sent.msg.Subject, "Entity A") {
			t.Fatalf("sent: %+v", sent.msg)
		}

		// A failure echoing the credentials is sanitized.
		ev.mailer.err = fmt.Errorf("%w: MAIL FROM: 550 pa55word mailer\x07 rejected", mail.ErrSMTP)
		res, err = ev.svc.TestSMTP(ctx, ev.adminA, ev.a.ID, "admin@entity-a.example.com", clientIP)
		mustNoErr(t, "failed test", err)
		if res.Success || res.Stage != StageEnvelope || strings.Contains(res.Error, "pa55word") ||
			strings.Contains(res.Error, "mailer") || strings.ContainsRune(res.Error, 7) {
			t.Fatalf("failure: %+v", res)
		}
		// A connect failure reports neither the addresses nor the OS error.
		ev.mailer.err = fmt.Errorf("%w: connect: dial tcp 10.1.2.3:25: connectex: refused", mail.ErrSMTP)
		res, err = ev.svc.TestSMTP(ctx, ev.adminA, ev.a.ID, "admin@entity-a.example.com", clientIP)
		mustNoErr(t, "connect failure", err)
		if res.Success || res.Stage != StageConnect || res.Error != connectFailed {
			t.Fatalf("connect failure: %+v", res)
		}
		ev.mailer.err = nil
		evs := ev.auditEvents(t, ev.a.ID, ActionTenantSMTPTested)
		if len(evs) != 3 || strings.Contains(string(evs[0].Details), "pa55word") {
			t.Fatalf("audit: %+v", evs)
		}

		_, err = ev.svc.TestSMTP(ctx, ev.adminA, ev.a.ID, "nope", clientIP)
		wantInvalid(t, "recipient", err, FieldTo)
		_, err = ev.svc.TestSMTP(ctx, ev.adminB, ev.a.ID, "admin@entity-a.example.com", clientIP)
		wantErr(t, "other tenant", err, ErrNotFound)

		// Rate limit: 5 per window per admin and tenant.
		for range 1 {
			_, err = ev.svc.TestSMTP(ctx, ev.adminA, ev.a.ID, "admin@entity-a.example.com", clientIP)
			mustNoErr(t, "within limit", err)
		}
		_, err = ev.svc.TestSMTP(ctx, ev.adminA, ev.a.ID, "admin@entity-a.example.com", clientIP)
		var rl *RateLimitError
		if !errors.As(err, &rl) || !errors.Is(err, ErrRateLimited) || rl.RetryAfter < time.Second || rl.Error() == "" {
			t.Fatalf("rate limit: %v", err)
		}
		_, err = ev.svc.TestSMTP(ctx, ev.super, ev.a.ID, "admin@entity-a.example.com", clientIP)
		mustNoErr(t, "another admin", err)
		ev.clock.Advance(DefaultSMTPTestWindow)
		_, err = ev.svc.TestSMTP(ctx, ev.adminA, ev.a.ID, "admin@entity-a.example.com", clientIP)
		mustNoErr(t, "after the window", err)
	})
}

func TestSMTPTestDenied(t *testing.T) {
	ctx := context.Background()
	// Settings saved before the deny list covered their host.
	ev := newEnv(t, storetest.SQLite(t), func(o *Options) { o.SMTPDenyNetworks = nil })
	_, err := ev.svc.UpdateSMTP(ctx, ev.adminA, ev.a.ID, SMTPUpdate{
		Host: "127.0.0.1", Port: 25, Security: store.SMTPSecurityNone, FromAddress: "noreply@entity-a.example.com",
	}, clientIP)
	mustNoErr(t, "loopback allowed", err)
	ev.svc.deny = mustPrefixes("127.0.0.0/8")
	res, err := ev.svc.TestSMTP(ctx, ev.adminA, ev.a.ID, "admin@entity-a.example.com", clientIP)
	mustNoErr(t, "test", err)
	if res.Success || res.Stage != StageConnect || res.Error != connectDenied || ev.mailer.count() != 0 {
		t.Fatalf("denied literal: %+v", res)
	}

	// A name resolving to the metadata address is refused when dialing.
	res2 := newFakeResolver()
	res2.ips["smtp.rebind.example.com"] = []netip.Addr{netip.MustParseAddr("169.254.169.254")}
	ev.svc.mailer = guardedMailer{guard: netpolicy.NewDialGuard(mustPrefixes("169.254.0.0/16"), res2), inner: ev.mailer}
	_, err = ev.svc.UpdateSMTP(ctx, ev.adminA, ev.a.ID, SMTPUpdate{
		Host: "smtp.rebind.example.com", Port: 25, Security: store.SMTPSecurityNone, FromAddress: "noreply@entity-a.example.com",
	}, clientIP)
	mustNoErr(t, "name saved", err)
	res, err = ev.svc.TestSMTP(ctx, ev.adminA, ev.a.ID, "admin@entity-a.example.com", clientIP)
	mustNoErr(t, "test", err)
	if res.Success || res.Stage != StageConnect || res.Error != connectDenied || strings.Contains(res.Error, "169.254") ||
		ev.mailer.count() != 0 {
		t.Fatalf("denied name: %+v", res)
	}
}

func TestSMTPTestFaults(t *testing.T) {
	ctx := context.Background()
	ev := newEnv(t, storetest.SQLite(t))
	_, err := ev.svc.UpdateSMTP(ctx, ev.adminA, ev.a.ID, authenticated("pw"), clientIP)
	mustNoErr(t, "settings", err)
	ev.faults("openSecret")
	_, err = ev.svc.TestSMTP(ctx, ev.adminA, ev.a.ID, "admin@entity-a.example.com", clientIP)
	wantErr(t, "unseal", err, errBoom)
}

func TestStageOf(t *testing.T) {
	for want, err := range map[string]error{
		StageConnect:  fmt.Errorf("%w: connect: refused", mail.ErrSMTP),
		StageSettings: fmt.Errorf("%w: x", mail.ErrInvalidSettings),
		StageStartTLS: mail.ErrStartTLSUnavailable,
		StageAuth:     fmt.Errorf("%w (code 535)", mail.ErrAuthFailed),
		StageTLS:      fmt.Errorf("%w: TLS handshake: x", mail.ErrSMTP),
		StageGreeting: fmt.Errorf("%w: EHLO: 500", mail.ErrSMTP),
		StageData:     fmt.Errorf("%w: end of DATA: 552", mail.ErrSMTP),
		StageUnknown:  errBoom,
	} {
		if got := stageOf(err); got != want {
			t.Errorf("stageOf(%v) = %s, want %s", err, got, want)
		}
	}
	// A username shorter than 3 characters is not redacted.
	if got := sanitizeReply("550 ab unknown", mail.Settings{Username: "ab"}); got != "550 ab unknown" {
		t.Errorf("short username: %q", got)
	}
	if got := sanitizeReply("550 abc unknown", mail.Settings{Username: "abc"}); got != "550 "+redacted+" unknown" {
		t.Errorf("username: %q", got)
	}
	long := sanitizeReply(strings.Repeat("é", 400), mail.Settings{})
	if len([]rune(long)) != maxReplyLen+3 {
		t.Errorf("not truncated: %d", len([]rune(long)))
	}
}

// TestSMTPTestMailpit sends the test mail to Mailpit through a DialGuard.
func TestSMTPTestMailpit(t *testing.T) {
	smtpAddr, api := os.Getenv("TT_TEST_MAILPIT_SMTP"), strings.TrimSuffix(os.Getenv("TT_TEST_MAILPIT_API"), "/")
	if smtpAddr == "" || api == "" {
		if os.Getenv("TT_TEST_REQUIRE_POSTGRES") == "1" {
			t.Fatal("TT_TEST_MAILPIT_SMTP and TT_TEST_MAILPIT_API are required when TT_TEST_REQUIRE_POSTGRES=1")
		}
		t.Skip("TT_TEST_MAILPIT_SMTP and TT_TEST_MAILPIT_API not set")
	}
	host, portText, err := net.SplitHostPort(smtpAddr)
	mustNoErr(t, "mailpit address", err)
	port, err := strconv.Atoi(portText)
	mustNoErr(t, "mailpit port", err)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sender := guardedMailer{
		guard: netpolicy.NewDialGuard(mustPrefixes("169.254.0.0/16"), nil),
		inner: mail.NewSMTPSender(mail.SMTPOptions{Timeout: 10 * time.Second}),
	}
	ev := newEnv(t, storetest.SQLite(t), func(o *Options) { o.SMTPDenyNetworks, o.Mailer = nil, sender })
	var raw [8]byte
	_, _ = rand.Read(raw[:])
	nonce := hex.EncodeToString(raw[:])
	_, err = ev.svc.UpdateTenant(ctx, ev.super, ev.a.ID, TenantUpdate{Name: ptr("Entity " + nonce)}, clientIP)
	mustNoErr(t, "rename", err)
	_, err = ev.svc.UpdateSMTP(ctx, ev.adminA, ev.a.ID, SMTPUpdate{
		Host: host, Port: port, Security: store.SMTPSecurityNone, FromAddress: "noreply@entity-a.example.com",
	}, clientIP)
	mustNoErr(t, "settings", err)
	res, err := ev.svc.TestSMTP(ctx, ev.adminA, ev.a.ID, "admin@entity-a.example.com", clientIP)
	mustNoErr(t, "test", err)
	if !res.Success || res.Stage != StageDone {
		t.Fatalf("result: %+v", res)
	}
	for {
		var list struct {
			Messages []struct{ Subject string } `json:"messages"`
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
			api+"/api/v1/search?query="+url.QueryEscape(`subject:"`+nonce+`"`), nil)
		resp, err := http.DefaultClient.Do(req)
		mustNoErr(t, "mailpit search", err)
		err = json.NewDecoder(resp.Body).Decode(&list)
		_ = resp.Body.Close()
		mustNoErr(t, "mailpit decode", err)
		if len(list.Messages) > 0 {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("test mail not found in Mailpit")
		case <-time.After(200 * time.Millisecond):
		}
	}
}
