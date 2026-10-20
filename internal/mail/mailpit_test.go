package mail

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// mailpitEnv returns the Mailpit SMTP address and API base URL. When they
// are not set it skips the test, or fails it under TT_TEST_REQUIRE_POSTGRES=1
// (make check, whose test target exports them and starts Mailpit).
func mailpitEnv(t *testing.T) (host string, port int, api string) {
	t.Helper()
	smtpAddr, api := os.Getenv("TT_TEST_MAILPIT_SMTP"), os.Getenv("TT_TEST_MAILPIT_API")
	if smtpAddr == "" || api == "" {
		if os.Getenv("TT_TEST_REQUIRE_POSTGRES") == "1" {
			t.Fatal("TT_TEST_MAILPIT_SMTP and TT_TEST_MAILPIT_API are required when TT_TEST_REQUIRE_POSTGRES=1")
		}
		t.Skip("TT_TEST_MAILPIT_SMTP and TT_TEST_MAILPIT_API not set")
	}
	h, p, err := net.SplitHostPort(smtpAddr)
	if err != nil {
		t.Fatalf("TT_TEST_MAILPIT_SMTP: %v", err)
	}
	port, err = strconv.Atoi(p)
	if err != nil {
		t.Fatalf("TT_TEST_MAILPIT_SMTP: %v", err)
	}
	return h, port, strings.TrimSuffix(api, "/")
}

// mailpitGet decodes a JSON response of the Mailpit API.
func mailpitGet(ctx context.Context, t *testing.T, u string, out any) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %s", u, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
}

func TestMailpit(t *testing.T) {
	host, port, api := mailpitEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// A unique nonce in the subject finds this very message through the
	// search API, whatever else the shared Mailpit holds.
	var raw [8]byte
	_, _ = rand.Read(raw[:])
	nonce := hex.EncodeToString(raw[:])
	tenant := "Entité A " + nonce
	msg, err := Render(TemplateVerificationCode, "fr", VerificationCodeData{TenantName: tenant, Code: "482916", ValidityMinutes: 15})
	if err != nil {
		t.Fatal(err)
	}
	msg.To = []string{"bob@entity-b.example.com"}
	st := Settings{
		Host: host, Port: port, Security: SecurityNone,
		FromAddress: "noreply@entity-a.example.com", FromName: tenant,
	}
	if err := NewSMTPSender(SMTPOptions{Timeout: 10 * time.Second}).Send(ctx, st, msg); err != nil {
		t.Fatalf("Send: %v", err)
	}

	type address struct{ Name, Address string }
	var found struct {
		ID      string
		Subject string
		From    address
		To      []address
	}
	for found.ID == "" {
		var list struct {
			Messages []struct {
				ID      string
				Subject string
				From    address
				To      []address
			} `json:"messages"`
		}
		mailpitGet(ctx, t, api+"/api/v1/search?query="+url.QueryEscape(`subject:"`+nonce+`"`), &list)
		for _, m := range list.Messages {
			if strings.Contains(m.Subject, nonce) {
				found = m
				break
			}
		}
		if found.ID == "" {
			select {
			case <-ctx.Done():
				t.Fatal("message not found in Mailpit")
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	if found.Subject != msg.Subject || found.From.Name != tenant || found.From.Address != st.FromAddress ||
		len(found.To) != 1 || found.To[0].Address != "bob@entity-b.example.com" {
		t.Errorf("headers seen by Mailpit: %+v", found)
	}

	var full struct {
		Text string
		HTML string
	}
	mailpitGet(ctx, t, api+"/api/v1/message/"+url.PathEscape(found.ID), &full)
	if !strings.Contains(full.Text, "482916") || !strings.Contains(full.HTML, "482916") ||
		!strings.Contains(full.HTML, `lang="fr"`) {
		t.Errorf("bodies seen by Mailpit:\n%s\n%s", full.Text, full.HTML)
	}
}
