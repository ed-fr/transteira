package deposit

import (
	"context"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestSMTPSettingsAgreeWithMail checks that the SMTP settings the store
// accepts are always usable by internal/mail, which the store cannot import:
// every security mode maps to a mail mode, and every accepted configuration
// passes mail.Settings.Validate once read back (as prepareMail builds it).
func TestSMTPSettingsAgreeWithMail(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		ev := newEnv(t, e)
		repo := ev.db.SMTPSettings()

		for _, sec := range []store.SMTPSecurity{store.SMTPSecurityNone, store.SMTPSecuritySTARTTLS, store.SMTPSecurityTLS} {
			switch mail.Security(sec) {
			case mail.SecurityNone, mail.SecurityStartTLS, mail.SecurityTLS:
			default:
				t.Errorf("store security %q has no mail counterpart", sec)
			}
		}

		base := store.SMTPConfig{Host: "smtp.example.com", Port: 587, Security: store.SMTPSecuritySTARTTLS, FromAddress: "noreply@example.com"}
		with := func(mutate func(*store.SMTPConfig)) store.SMTPConfig {
			c := base
			mutate(&c)
			return c
		}
		candidates := []store.SMTPConfig{
			base,
			with(func(c *store.SMTPConfig) { c.Security, c.Port, c.Host = store.SMTPSecurityNone, 25, "smtp-relay" }),
			with(func(c *store.SMTPConfig) { c.Security, c.Port, c.Host = store.SMTPSecurityTLS, 465, "10.0.0.25" }),
			with(func(c *store.SMTPConfig) { c.Host = "fd00::25" }),
			with(func(c *store.SMTPConfig) { c.Host = strings.Repeat("a", 253) }),
			with(func(c *store.SMTPConfig) { c.Username = strings.Repeat("u", 320) }),
			with(func(c *store.SMTPConfig) { c.Username = strings.Repeat("ü", 160) }),
			with(func(c *store.SMTPConfig) { c.Username = strings.Repeat("ü", 161) }),
			with(func(c *store.SMTPConfig) { c.Username = "mailer@example.com" }),
			with(func(c *store.SMTPConfig) { c.Username = "a\tb" }),
			with(func(c *store.SMTPConfig) { c.Username, c.Security = "mailer", store.SMTPSecurityNone }),
			with(func(c *store.SMTPConfig) { c.FromName = strings.Repeat("é", 100) }),
			with(func(c *store.SMTPConfig) { c.FromName = "Entité A — Transfert" }),
			with(func(c *store.SMTPConfig) { c.FromName = "Entity\xe2\x80\xa8A" }),
			with(func(c *store.SMTPConfig) { c.FromName = "Entity\xc2\x85A" }),
			with(func(c *store.SMTPConfig) { c.FromAddress = " NoReply@Entity-A.Example.com " }),
		}
		for _, addr := range []string{
			"a.b+c@example.com", "o'brien@example.com", "x!#$%&*/=?^_`{|}~-@example.com",
			"noreply@sub.entity-a.example.com", strings.Repeat("a", 64) + "@example.com",
			`"quoted"@example.com`, "Name <a@example.com>", "a@[192.0.2.1]", "a@localhost", "jöhn@example.com",
			"a@bücher.example", "a..b@example.com", ".a@example.com", "a@-example.com", "a@example-.com",
			"a@example.com.", "a@example.123", "user@xn--a.example.com", "a@" + strings.Repeat("b", 64) + ".com",
			"a@" + strings.Repeat("b.", 126) + "com", "a b@example.com", "a@example.com (comment)",
		} {
			candidates = append(candidates, with(func(c *store.SMTPConfig) { c.FromAddress = addr }))
		}

		secret, err := ev.vault.Seal(ctx, ev.c.ID, crypto.PurposeSecret, []byte("secret"))
		if err != nil {
			t.Fatal(err)
		}
		candidates = append(candidates,
			with(func(c *store.SMTPConfig) { c.PasswordKeyID = secret }),
			with(func(c *store.SMTPConfig) { c.PasswordKeyID, c.Username = secret, "mailer" }),
			with(func(c *store.SMTPConfig) {
				c.PasswordKeyID, c.Username, c.Security = secret, "mailer", store.SMTPSecurityNone
			}),
		)

		accepted := 0
		for _, c := range candidates {
			if err := repo.Put(ctx, ev.c.ID, c); err != nil {
				continue
			}
			accepted++
			got, err := repo.Get(ctx, ev.c.ID)
			if err != nil {
				t.Fatal(err)
			}
			settings := mail.Settings{
				Host: got.Host, Port: got.Port, Security: mail.Security(got.Security), Username: got.Username,
				FromAddress: got.FromAddress, FromName: got.FromName,
			}
			if got.PasswordKeyID != "" {
				settings.Password = "secret"
			}
			if err := settings.Validate(); err != nil {
				t.Errorf("store accepted %+v, mail refuses it: %v", c, err)
			}
			// The raw sender address the store accepted is accepted by
			// mail.ParseAddress too (store trims it first).
			if _, err := mail.ParseAddress(strings.TrimSpace(c.FromAddress)); err != nil {
				t.Errorf("store accepted the sender %q, mail.ParseAddress refuses it: %v", c.FromAddress, err)
			}
		}
		if accepted < 15 || accepted == len(candidates) {
			t.Errorf("%d of %d candidates accepted: the table no longer exercises both sides", accepted, len(candidates))
		}
	})
}
