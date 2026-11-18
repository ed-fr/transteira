package integration_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/cli/secret"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestCLIExpressSecret: the library of transteira-cli secret create and
// secret read (internal/cli/secret) against the real server, through the TLS
// front of cli_helpers_test.go. An anonymous creation and one with a token
// allowed for express secrets are read once with their link: the text as
// typed, the express and anonymous markers of the status; a second reading
// is gone. An ordinary token is refused (express-token-not-allowed).
// Closing the anonymous mode refuses the anonymous creations and blocks the
// reading of an anonymous secret without consuming it, while a secret
// created with the token stays readable; reopening makes the blocked one
// readable again. An unknown link is not found. No path through the front
// carries the key, and the audit holds neither the key nor the text (T-389,
// T-399, T-402, T-406).
func TestCLIExpressSecret(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		o := startOps(t, e)
		o.openExpress(t, o.tid, nil)
		front := startCLIFront(t, o.server, scriptIP)
		_, allowed := o.expressTokenOf(t, o.tid, "cli express", []string{scriptNet}, true)
		_, ordinary := o.expressTokenOf(t, o.tid, "cli deposit", []string{scriptNet}, false)
		withToken := front.newClient(t, hostA, allowed, "")
		reader := front.newClient(t, hostA, "", "")
		ctx := t.Context()

		var keys []string
		create := func(c *client.Client, text string, anonymous bool) secret.Link {
			t.Helper()
			created, err := secret.Create(ctx, c, secret.CreateOptions{Text: text, Duration: "1h", Anonymous: anonymous})
			if err != nil {
				t.Fatalf("Create %q: %v", text, err)
			}
			if created.Anonymous != anonymous || !strings.HasPrefix(created.Link, "https://"+hostA+"/s/tts_") {
				t.Fatalf("Create %q: %+v", text, created)
			}
			l, err := secret.ParseLink(created.Link)
			if err != nil {
				t.Fatalf("ParseLink of the created link: %v", err)
			}
			keys = append(keys, l.Key)
			o.secret(l.Key, text)
			return l
		}
		read := func(l secret.Link, text string, anonymous bool) {
			t.Helper()
			rv, err := secret.Read(ctx, reader, l)
			if err != nil {
				t.Fatalf("Read %q: %v", text, err)
			}
			if rv.Text != text || !rv.Express || rv.Anonymous != anonymous || rv.FileLost {
				t.Fatalf("Read %q: %+v", text, rv)
			}
		}
		refused := func(what string, err, want error) {
			t.Helper()
			if !errors.Is(err, want) {
				t.Fatalf("%s: %v, want %v", what, err, want)
			}
		}

		// Created anonymously, then with the token; each read once.
		const anonText, tokenText = "Code d'accès : 4F7#kp9\nÉté 😀", "token text\twith a tab"
		anonLink := create(reader, anonText, true)
		read(anonLink, anonText, true)
		_, err := secret.Read(ctx, reader, anonLink)
		refused("second reading", err, secret.ErrGone)
		tokenLink := create(withToken, tokenText, false)
		read(tokenLink, tokenText, false)

		// An ordinary token may not create express secrets.
		_, err = secret.Create(ctx, front.newClient(t, hostA, ordinary, ""), secret.CreateOptions{Text: "x"})
		refused("ordinary token", err, secret.ErrTokenNotAllowed)

		// Closed anonymous mode: anonymous creations refused, the anonymous
		// secret blocked (nothing consumed), the token one still readable.
		blocked := create(reader, "blocked while closed", true)
		mustStatus(t, "close the anonymous express secrets",
			setExpressSettings(t, o.sa, o.tid, map[string]any{"expressEnabled": false}), http.StatusOK)
		_, err = secret.Create(ctx, reader, secret.CreateOptions{Text: "x"})
		refused("anonymous creation while closed", err, secret.ErrDisabled)
		_, err = secret.Read(ctx, reader, blocked)
		refused("anonymous reading while closed", err, secret.ErrDisabled)
		read(create(withToken, "token while closed", false), "token while closed", false)
		o.openExpress(t, o.tid, nil)
		read(blocked, "blocked while closed", true)

		// An unknown link.
		unknown := secret.Link{Origin: "https://" + hostA, Token: "tts_" + strings.Repeat("Z", 43), Key: strings.Repeat("A", 43)}
		_, err = secret.Read(ctx, reader, unknown)
		refused("unknown link", err, secret.ErrNotFound)

		front.mu.Lock()
		requests := append([]string(nil), front.requests...)
		front.mu.Unlock()
		for _, r := range requests {
			for _, k := range keys {
				if strings.Contains(r, k) || strings.Contains(r, "#") {
					t.Errorf("a request through the front carries a key or a fragment: %s", r)
				}
			}
		}
		o.expectNoSecrets(t, o.tenantAudit(t, o.tid))
	})
}
