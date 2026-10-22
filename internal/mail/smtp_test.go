package mail

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	netmail "net/mail"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	testUser = "relay-user"
	testPass = "not-a-real-password"
)

// testSettings returns valid settings for a fake server on port.
func testSettings(port int, sec Security) Settings {
	return Settings{
		Host:        "127.0.0.1",
		Port:        port,
		Security:    sec,
		FromAddress: "noreply@entity-a.example.com",
		FromName:    "Entity A",
	}
}

// testMessage returns a valid message.
func testMessage() Message {
	return Message{
		To:       []string{"bob@example.com", "carol@Entity-B.example.com"},
		Subject:  "Votre code de vérification",
		Text:     "Bonjour,\nvotre code est 123456.\n",
		HTML:     "<p>Bonjour, votre code est <b>123456</b>.</p>\n",
		Language: "fr",
	}
}

// testSender returns a sender trusting the test certificate.
func testSender(timeout time.Duration) *SMTPSender {
	_, pool := testCert()
	return NewSMTPSender(SMTPOptions{Timeout: timeout, RootCAs: pool, HelloName: "tt.example.com"})
}

func TestSendModes(t *testing.T) {
	cases := []struct {
		name     string
		fake     *fakeSMTP
		sec      Security
		auth     bool
		wantTLS  bool
		wantAuth bool
	}{
		{"none", &fakeSMTP{}, SecurityNone, false, false, false},
		{"none ignores offered starttls", &fakeSMTP{offerStartTLS: true}, SecurityNone, false, false, false},
		{"starttls", &fakeSMTP{offerStartTLS: true}, SecurityStartTLS, false, true, false},
		{"starttls auth", &fakeSMTP{offerStartTLS: true, user: testUser, pass: testPass}, SecurityStartTLS, true, true, true},
		{"tls", &fakeSMTP{implicitTLS: true}, SecurityTLS, false, true, false},
		{"tls auth", &fakeSMTP{implicitTLS: true, user: testUser, pass: testPass}, SecurityTLS, true, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := startFake(t, c.fake)
			st := testSettings(f.port(), c.sec)
			if c.auth {
				st.Username, st.Password = testUser, testPass
			}
			if err := testSender(5*time.Second).Send(context.Background(), st, testMessage()); err != nil {
				t.Fatalf("Send: %v", err)
			}
			msgs := f.messages()
			if len(msgs) != 1 {
				t.Fatalf("got %d messages", len(msgs))
			}
			m := msgs[0]
			if m.tls != c.wantTLS || m.authed != c.wantAuth {
				t.Errorf("tls=%v authed=%v, want %v %v", m.tls, m.authed, c.wantTLS, c.wantAuth)
			}
			if m.from != "noreply@entity-a.example.com" {
				t.Errorf("envelope from %q", m.from)
			}
			if strings.Join(m.to, ",") != "bob@example.com,carol@entity-b.example.com" {
				t.Errorf("envelope to %v", m.to)
			}
			checkParsedMessage(t, m.data)
		})
	}
}

// checkParsedMessage parses a message built from testMessage back with
// net/mail and mime/multipart.
func checkParsedMessage(t *testing.T, raw []byte) {
	t.Helper()
	msg, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	dec := new(mime.WordDecoder)
	subject, err := dec.DecodeHeader(msg.Header.Get("Subject"))
	if err != nil || subject != "Votre code de vérification" {
		t.Errorf("subject %q, %v", subject, err)
	}
	from, err := msg.Header.AddressList("From")
	if err != nil || len(from) != 1 || from[0].Name != "Entity A" || from[0].Address != "noreply@entity-a.example.com" {
		t.Errorf("from %v, %v", from, err)
	}
	to, err := msg.Header.AddressList("To")
	if err != nil || len(to) != 2 {
		t.Errorf("to %v, %v", to, err)
	}
	if _, err := msg.Header.Date(); err != nil {
		t.Errorf("date: %v", err)
	}
	if id := msg.Header.Get("Message-ID"); !strings.HasPrefix(id, "<") || !strings.HasSuffix(id, "@entity-a.example.com>") || len(id) != len("<@entity-a.example.com>")+32 {
		t.Errorf("message-id %q", id)
	}
	if msg.Header.Get("MIME-Version") != "1.0" || msg.Header.Get("Content-Language") != "fr" ||
		msg.Header.Get("Auto-Submitted") != "auto-generated" {
		t.Errorf("headers %v", msg.Header)
	}
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Fatalf("content type %q, %v", mt, err)
	}
	parts := readParts(t, multipart.NewReader(msg.Body, params["boundary"]))
	if len(parts) != 2 || parts[0].ctype != "text/plain; charset=utf-8" || parts[1].ctype != "text/html; charset=utf-8" {
		t.Fatalf("parts %+v", parts)
	}
	if parts[0].body != "Bonjour,\r\nvotre code est 123456.\r\n" {
		t.Errorf("text %q", parts[0].body)
	}
	if !strings.Contains(parts[1].body, "<b>123456</b>") {
		t.Errorf("html %q", parts[1].body)
	}
}

// part is a decoded MIME part.
type part struct {
	ctype, body string
	header      map[string][]string
}

// readParts reads every part of r (quoted-printable is decoded by
// mime/multipart).
func readParts(t *testing.T, r *multipart.Reader) []part {
	t.Helper()
	var out []part
	for {
		p, err := r.NextPart()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		b, err := io.ReadAll(p)
		if err != nil {
			t.Fatalf("read part: %v", err)
		}
		out = append(out, part{ctype: p.Header.Get("Content-Type"), body: string(b), header: p.Header})
	}
}

func TestSendStartTLSMissing(t *testing.T) {
	f := startFake(t, &fakeSMTP{})
	err := testSender(5*time.Second).Send(context.Background(), testSettings(f.port(), SecurityStartTLS), testMessage())
	if !errors.Is(err, ErrStartTLSUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if len(f.messages()) != 0 {
		t.Fatal("message delivered without STARTTLS")
	}
}

func TestSendUntrustedCertificate(t *testing.T) {
	for _, c := range []struct {
		fake *fakeSMTP
		sec  Security
	}{
		{&fakeSMTP{implicitTLS: true}, SecurityTLS},
		{&fakeSMTP{offerStartTLS: true}, SecurityStartTLS},
	} {
		f := startFake(t, c.fake)
		s := NewSMTPSender(SMTPOptions{Timeout: 5 * time.Second}) // system roots only
		err := s.Send(context.Background(), testSettings(f.port(), c.sec), testMessage())
		if !errors.Is(err, ErrSMTP) || !strings.Contains(err.Error(), "certificate") {
			t.Errorf("%s: err = %v", c.sec, err)
		}
	}
}

func TestSendAuthErrors(t *testing.T) {
	t.Run("auth not offered", func(t *testing.T) {
		f := startFake(t, &fakeSMTP{offerStartTLS: true})
		st := testSettings(f.port(), SecurityStartTLS)
		st.Username, st.Password = testUser, testPass
		if err := testSender(5*time.Second).Send(context.Background(), st, testMessage()); !errors.Is(err, ErrAuthUnavailable) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("wrong password", func(t *testing.T) {
		f := startFake(t, &fakeSMTP{implicitTLS: true, user: testUser, pass: "other"})
		st := testSettings(f.port(), SecurityTLS)
		st.Username, st.Password = testUser, testPass
		err := testSender(5*time.Second).Send(context.Background(), st, testMessage())
		if !errors.Is(err, ErrAuthFailed) || !strings.Contains(err.Error(), "code 535") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("server echoes the password", func(t *testing.T) {
		f := startFake(t, &fakeSMTP{
			implicitTLS: true, user: testUser, pass: testPass,
			replies: map[string]string{"AUTH": "535 nope " + testPass},
		})
		st := testSettings(f.port(), SecurityTLS)
		st.Username, st.Password = testUser, testPass
		err := testSender(5*time.Second).Send(context.Background(), st, testMessage())
		if !errors.Is(err, ErrAuthFailed) || strings.Contains(err.Error(), testPass) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("auth failure without SMTP reply", func(t *testing.T) {
		f := startFake(t, &fakeSMTP{
			implicitTLS: true, user: testUser, pass: testPass,
			replies: map[string]string{"AUTH": "close"},
		})
		st := testSettings(f.port(), SecurityTLS)
		st.Username, st.Password = testUser, testPass
		err := testSender(5*time.Second).Send(context.Background(), st, testMessage())
		if !errors.Is(err, ErrAuthFailed) || strings.Contains(err.Error(), "code") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestSendScrubsPassword(t *testing.T) {
	plain := base64.StdEncoding.EncodeToString([]byte("\x00" + testUser + "\x00" + testPass))
	for _, echo := range []string{testPass, plain} {
		f := startFake(t, &fakeSMTP{
			implicitTLS: true, user: testUser, pass: testPass,
			replies: map[string]string{"RCPT": "550 rejected, by the way: " + echo},
		})
		st := testSettings(f.port(), SecurityTLS)
		st.Username, st.Password = testUser, testPass
		err := testSender(5*time.Second).Send(context.Background(), st, testMessage())
		if err == nil || strings.Contains(err.Error(), testPass) || strings.Contains(err.Error(), plain) {
			t.Fatalf("err = %v", err)
		}
		if !errors.Is(err, ErrSMTP) || !strings.Contains(err.Error(), redacted) {
			t.Fatalf("sentinel lost or not redacted: %v", err)
		}
	}
}

func TestScrubKeepsSentinels(t *testing.T) {
	st := Settings{Username: "u", Password: "pw"}
	err := scrub(errors.Join(context.DeadlineExceeded, ErrAuthFailed, errors.New("pw")), st)
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrAuthFailed) || errors.Is(err, ErrSMTP) {
		t.Fatalf("sentinels: %v", err)
	}
	if strings.Contains(err.Error(), "pw") {
		t.Fatalf("not scrubbed: %v", err)
	}
	plainErr := errors.New("x")
	if got := scrub(plainErr, st); got != plainErr { //nolint:errorlint // identity is the point: the error must pass through untouched
		t.Fatal("clean errors must pass through unchanged")
	}
	if got := scrub(plainErr, Settings{}); got != plainErr { //nolint:errorlint // identity, as above
		t.Fatal("clean errors must pass through unchanged")
	}
}

func TestSendProtocolErrors(t *testing.T) {
	cases := map[string]struct {
		fake *fakeSMTP
		sec  Security
		want string
	}{
		"greeting":      {&fakeSMTP{replies: map[string]string{"GREETING": "554 go away"}}, SecurityNone, "greeting"},
		"ehlo":          {&fakeSMTP{replies: map[string]string{"EHLO": "500 no", "HELO": "500 no"}}, SecurityNone, "EHLO"},
		"starttls":      {&fakeSMTP{offerStartTLS: true, replies: map[string]string{"STARTTLS": "454 not now"}}, SecurityStartTLS, "STARTTLS"},
		"mail from":     {&fakeSMTP{replies: map[string]string{"MAIL": "550 sender refused"}}, SecurityNone, "MAIL FROM"},
		"rcpt":          {&fakeSMTP{replies: map[string]string{"RCPT": "550 <bob@example.com> unknown"}}, SecurityNone, "RCPT TO"},
		"data":          {&fakeSMTP{replies: map[string]string{"DATA": "554 no data"}}, SecurityNone, "DATA"},
		"end of data":   {&fakeSMTP{replies: map[string]string{"DATAEND": "552 too big"}}, SecurityNone, "end of DATA"},
		"tls handshake": {&fakeSMTP{}, SecurityTLS, "TLS handshake"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := startFake(t, c.fake)
			err := testSender(2*time.Second).Send(context.Background(), testSettings(f.port(), c.sec), testMessage())
			if !errors.Is(err, ErrSMTP) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestSendQuitFailureIgnored(t *testing.T) {
	f := startFake(t, &fakeSMTP{replies: map[string]string{"QUIT": "close"}})
	if err := testSender(5*time.Second).Send(context.Background(), testSettings(f.port(), SecurityNone), testMessage()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(f.messages()) != 1 {
		t.Fatal("message not delivered")
	}
}

func TestSendTimeout(t *testing.T) {
	f := startFake(t, &fakeSMTP{silent: true})
	start := time.Now()
	err := testSender(200*time.Millisecond).Send(context.Background(), testSettings(f.port(), SecurityNone), testMessage())
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrSMTP) {
		t.Fatalf("err = %v", err)
	}
	// Generous bound: under a loaded make check the 200 ms deadline can fire
	// seconds late; the test only proves the send does not hang.
	if d := time.Since(start); d > 15*time.Second {
		t.Fatalf("timeout not honored: %v", d)
	}
}

func TestSendContextCancel(t *testing.T) {
	f := startFake(t, &fakeSMTP{silent: true})
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	err := testSender(time.Minute).Send(ctx, testSettings(f.port(), SecurityNone), testMessage())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("cancellation not honored: %v", d)
	}
}

func TestSendDialFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	err = testSender(2*time.Second).Send(context.Background(), testSettings(port, SecurityNone), testMessage())
	if !errors.Is(err, ErrSMTP) || !strings.Contains(err.Error(), "connect") {
		t.Fatalf("err = %v", err)
	}
}

func TestSendValidatesFirst(t *testing.T) {
	s := NewSMTPSender(SMTPOptions{})
	if s.timeout != DefaultTimeout || s.helloName != defaultHelloName {
		t.Fatalf("defaults: %v %q", s.timeout, s.helloName)
	}
	s.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("dialed despite invalid input")
		return nil, nil
	}
	if err := s.Send(context.Background(), Settings{}, testMessage()); !errors.Is(err, ErrInvalidSettings) {
		t.Fatalf("settings: %v", err)
	}
	m := testMessage()
	m.Subject = "x\r\nBcc: eve@example.com"
	if err := s.Send(context.Background(), testSettings(25, SecurityNone), m); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("message: %v", err)
	}
}

func TestWithContextError(t *testing.T) {
	ioTimeout := fmt.Errorf("%w: greeting: %w", ErrSMTP, os.ErrDeadlineExceeded)
	// The I/O deadline fired before the context noticed: still a deadline.
	err := withContextError(context.Background(), ioTimeout)
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrSMTP) {
		t.Errorf("io timeout: %v", err)
	}
	other := fmt.Errorf("%w: refused", ErrSMTP)
	if got := withContextError(context.Background(), other); got != other { //nolint:errorlint // identity: untouched
		t.Errorf("other: %v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = withContextError(ctx, ioTimeout)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("canceled: %v", err)
	}
	already := fmt.Errorf("dial: %w", context.Canceled)
	if got := withContextError(ctx, already); got != already { //nolint:errorlint // identity: not wrapped twice
		t.Errorf("already wrapped: %v", got)
	}
}

func TestSendCustomDial(t *testing.T) {
	var gotNetwork, gotAddr string
	dialErr := errors.New("refused by the guard")
	s := NewSMTPSender(SMTPOptions{Timeout: 2 * time.Second, Dial: func(_ context.Context, network, addr string) (net.Conn, error) {
		gotNetwork, gotAddr = network, addr
		return nil, dialErr
	}})
	err := s.Send(context.Background(), testSettings(2525, SecurityNone), testMessage())
	if !errors.Is(err, ErrSMTP) || !errors.Is(err, dialErr) {
		t.Fatalf("err = %v", err)
	}
	if gotNetwork != "tcp" || gotAddr != "127.0.0.1:2525" {
		t.Fatalf("dial(%q, %q)", gotNetwork, gotAddr)
	}
}
