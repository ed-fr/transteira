package mail

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	netmail "net/mail"
	"strings"
	"testing"
	"time"
)

func TestParseAddress(t *testing.T) {
	ok := map[string]string{
		"bob@example.com":                     "bob@example.com",
		"Bob.Smith@Entity-A.Example.COM":      "Bob.Smith@entity-a.example.com",
		"a+tag@sub.entity-b.example.com":      "a+tag@sub.entity-b.example.com",
		"o'neil@example.com":                  "o'neil@example.com",
		"x@transfer.entity-a.localhost":       "x@transfer.entity-a.localhost",
		"!#$%&'*+-/=?^_`{|}~@example.com":     "!#$%&'*+-/=?^_`{|}~@example.com",
		strings.Repeat("l", 64) + "@ex.com":   strings.Repeat("l", 64) + "@ex.com",
		"a@" + strings.Repeat("d", 63) + ".a": "a@" + strings.Repeat("d", 63) + ".a",
	}
	for in, want := range ok {
		got, err := ParseAddress(in)
		if err != nil || got != want {
			t.Errorf("ParseAddress(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", "bob", "bob@", "@example.com", "bob@example", "bob@localhost",
		"bob@example.com\r\nBcc: eve@example.com", "bob@example.com\n", "bob\r@example.com",
		"bob@example.com\x00", " bob@example.com", "bob@example.com ", "<bob@example.com>",
		"Bob <bob@example.com>", `"bob smith"@example.com`, `"bob"@example.com`, "bob@[127.0.0.1]",
		"bob..x@example.com", ".bob@example.com", "bob.@example.com", "bob@-example.com",
		"bob@example-.com", "bob@exa_mple.com", "bob@example..com", "bob@.example.com",
		"bób@example.com", "bob@exämple.com", "bob(comment)@example.com", "bob@example.com,eve@example.com",
		"a@b@example.com", strings.Repeat("l", 65) + "@example.com",
		"a@" + strings.Repeat("d", 64) + ".com", "a@" + strings.Repeat("d.", 130) + "com",
		"bob@example.com ",
	}
	for _, in := range bad {
		if got, err := ParseAddress(in); err == nil || !errors.Is(err, ErrInvalidAddress) {
			t.Errorf("ParseAddress(%q) = %q, %v; want ErrInvalidAddress", in, got, err)
		}
	}
}

func FuzzAddress(f *testing.F) {
	for _, s := range []string{
		"bob@example.com", "Bob <bob@example.com>", "bob@example.com\r\nBcc: x@example.com",
		`"a b"@example.com`, "=?utf-8?q?x?=@example.com", "a@b.c",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		addr, err := ParseAddress(s)
		if err != nil {
			return
		}
		for i := range len(addr) {
			if addr[i] <= ' ' || addr[i] > '~' || strings.IndexByte(`<>()[]\,;:"`, addr[i]) >= 0 {
				t.Fatalf("accepted %q with unsafe byte %q", addr, addr[i])
			}
		}
		parsed, err := netmail.ParseAddress(addr)
		if err != nil || parsed.Address != addr || parsed.Name != "" {
			t.Fatalf("net/mail disagrees on %q: %v %v", addr, parsed, err)
		}
		if again, err := ParseAddress(addr); err != nil || again != addr {
			t.Fatalf("not idempotent: %q -> %q, %v", addr, again, err)
		}
	})
}

func TestSettingsValidate(t *testing.T) {
	valid := Settings{
		Host: "smtp.example.com", Port: 587, Security: SecurityStartTLS,
		Username: "u", Password: "pw-marker-42", FromAddress: "noreply@example.com", FromName: "Entité A",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid: %v", err)
	}
	for _, h := range []string{"relay", "10.0.0.25", "::1", "smtp_relay.internal"} {
		s := valid
		s.Host = h
		if err := s.Validate(); err != nil {
			t.Errorf("host %q: %v", h, err)
		}
	}
	mutations := map[string]func(*Settings){
		"no host":        func(s *Settings) { s.Host = "" },
		"long host":      func(s *Settings) { s.Host = strings.Repeat("a", 254) },
		"host with port": func(s *Settings) { s.Host = "smtp.example.com/x" },
		"host crlf":      func(s *Settings) { s.Host = "smtp.example.com\r\n" },
		"host space":     func(s *Settings) { s.Host = "smtp example.com" },
		"port 0":         func(s *Settings) { s.Port = 0 },
		"port high":      func(s *Settings) { s.Port = 65536 },
		"security":       func(s *Settings) { s.Security = "ssl" },
		"empty security": func(s *Settings) { s.Security = "" },
		"from":           func(s *Settings) { s.FromAddress = "Entity <noreply@example.com>" },
		"from crlf":      func(s *Settings) { s.FromAddress = "noreply@example.com\r\nBcc: x@example.com" },
		"name crlf":      func(s *Settings) { s.FromName = "A\r\nBcc: x@example.com" },
		"name long":      func(s *Settings) { s.FromName = strings.Repeat("é", 101) },
		"name utf8":      func(s *Settings) { s.FromName = "\xff" },
		"user crlf":      func(s *Settings) { s.Username = "u\r\n" },
		"user long":      func(s *Settings) { s.Username = strings.Repeat("u", 321) },
		"password crlf":  func(s *Settings) { s.Password = "p\n" },
		"password long":  func(s *Settings) { s.Password = strings.Repeat("p", 1025) },
		"password alone": func(s *Settings) { s.Username = "" },
		"auth on none":   func(s *Settings) { s.Security = SecurityNone },
	}
	for name, mut := range mutations {
		s := valid
		mut(&s)
		err := s.Validate()
		if !errors.Is(err, ErrInvalidSettings) {
			t.Errorf("%s: err = %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), s.Password) && s.Password != "" {
			t.Errorf("%s: error leaks the password: %v", name, err)
		}
	}
	none := valid
	none.Security, none.Username, none.Password = SecurityNone, "", ""
	if err := none.Validate(); err != nil {
		t.Errorf("none without auth: %v", err)
	}
}

func TestSettingsRedaction(t *testing.T) {
	s := Settings{
		Host: "smtp.example.com", Port: 465, Security: SecurityTLS, Username: "u",
		Password: "very-secret-value", FromAddress: "noreply@example.com",
	}
	var logBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuf, nil)).Info("x", "smtp", s)
	for _, out := range []string{
		s.String(), fmt.Sprintf("%v", s), fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s),
		logBuf.String(),
	} {
		if strings.Contains(out, "very-secret-value") {
			t.Errorf("password leaked: %s", out)
		}
		if !strings.Contains(out, "smtp.example.com") {
			t.Errorf("host missing: %s", out)
		}
	}
	if !strings.Contains(s.String(), redacted) || !strings.Contains(logBuf.String(), `"password_set":true`) {
		t.Errorf("redaction marker missing: %s / %s", s.String(), logBuf.String())
	}
	if !strings.HasPrefix(s.GoString(), "mail.Settings{") {
		t.Errorf("GoString: %s", s.GoString())
	}
	s.Password = ""
	if strings.Contains(s.String(), "password") {
		t.Errorf("no password: %s", s.String())
	}
}

// buildSettings returns valid settings for Build tests.
func buildSettings() Settings {
	return Settings{
		Host: "smtp.example.com", Port: 25, Security: SecurityNone,
		FromAddress: "noreply@entity-a.example.com", FromName: "Entity A",
	}
}

func TestBuildTextOnly(t *testing.T) {
	m := Message{To: []string{"bob@example.com"}, Subject: "Hello", Text: "line one\nline two é\n", Language: "xx"}
	now := time.Date(2026, 10, 20, 9, 30, 0, 0, time.UTC)
	raw, err := build(buildSettings(), m, now)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.Get("Date") != "Tue, 20 Oct 2026 09:30:00 +0000" {
		t.Errorf("date %q", msg.Header.Get("Date"))
	}
	if msg.Header.Get("Content-Language") != "" {
		t.Error("unsupported language must not be written")
	}
	if msg.Header.Get("Content-Type") != "text/plain; charset=utf-8" || msg.Header.Get("Content-Transfer-Encoding") != "quoted-printable" {
		t.Errorf("headers %v", msg.Header)
	}
	body, _ := io.ReadAll(msg.Body)
	if !strings.Contains(string(body), "line two =C3=A9\r\n") {
		t.Errorf("body %q", body)
	}
	checkCRLF(t, raw)
}

// checkCRLF fails if raw holds a bare CR or LF.
func checkCRLF(t *testing.T, raw []byte) {
	t.Helper()
	for i, c := range raw {
		if c == '\n' && (i == 0 || raw[i-1] != '\r') {
			t.Fatalf("bare LF at %d", i)
		}
		if c == '\r' && (i+1 == len(raw) || raw[i+1] != '\n') {
			t.Fatalf("bare CR at %d", i)
		}
	}
}

func TestBuildInline(t *testing.T) {
	png := bytes.Repeat([]byte{0x89, 'P', 'N', 'G', 0, 1, 2, 3}, 40)
	m := testMessage()
	m.HTML = `<p><img src="cid:qr@transteira" alt="QR code"></p>`
	m.Inline = []InlinePart{
		{ContentID: "qr@transteira", ContentType: "image/png", Filename: "qr.png", Data: png},
		{ContentID: "logo", ContentType: "image/svg+xml", Data: []byte("<svg/>")},
	}
	raw, err := Build(buildSettings(), m)
	if err != nil {
		t.Fatal(err)
	}
	checkCRLF(t, raw)
	msg, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/related" || params["type"] != "multipart/alternative" {
		t.Fatalf("content type %q %v %v", mt, params, err)
	}
	r := multipart.NewReader(msg.Body, params["boundary"])
	first, err := r.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	amt, aparams, _ := mime.ParseMediaType(first.Header.Get("Content-Type"))
	if amt != "multipart/alternative" {
		t.Fatalf("first part %q", amt)
	}
	alt := readParts(t, multipart.NewReader(first, aparams["boundary"]))
	if len(alt) != 2 || !strings.Contains(alt[1].body, "cid:qr@transteira") {
		t.Fatalf("alternative %+v", alt)
	}
	rest := readParts(t, r)
	if len(rest) != 2 {
		t.Fatalf("inline parts %d", len(rest))
	}
	p := rest[0]
	if p.ctype != "image/png" || p.header["Content-Id"][0] != "<qr@transteira>" ||
		p.header["Content-Disposition"][0] != `inline; filename="qr.png"` {
		t.Errorf("inline headers %v", p.header)
	}
	data, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(p.body, "\r\n", ""))
	if err != nil || !bytes.Equal(data, png) {
		t.Errorf("inline data mismatch: %v", err)
	}
	for _, l := range strings.Split(strings.TrimSpace(p.body), "\r\n") {
		if len(l) > base64LineLen {
			t.Errorf("base64 line of %d characters", len(l))
		}
	}
	if rest[1].header["Content-Disposition"][0] != "inline" {
		t.Errorf("second inline %v", rest[1].header)
	}
}

func TestBuildHeaderEncoding(t *testing.T) {
	dec := new(mime.WordDecoder)
	cases := []struct{ subject, name string }{
		{"Plain ASCII subject", `Entity "A" \ Ltd`},
		{"Looks =?utf-8?q?encoded?=", "=?utf-8?q?fake?="},
		{strings.Repeat("Données très confidentielles ", 8), "Entité Ä — Société"},
		{"日本語の件名" + strings.Repeat("é", 200), strings.Repeat("ü", 100)},
	}
	for _, c := range cases {
		s := buildSettings()
		s.FromName = c.name
		m := Message{To: []string{"bob@example.com"}, Subject: c.subject, Text: "x"}
		raw, err := Build(s, m)
		if err != nil {
			t.Fatalf("%q: %v", c.subject, err)
		}
		checkCRLF(t, raw)
		head, _, _ := bytes.Cut(raw, []byte("\r\n\r\n"))
		for _, l := range strings.Split(string(head), "\r\n") {
			if len(l) > 998 {
				t.Errorf("header line of %d bytes", len(l))
			}
		}
		msg, err := netmail.ReadMessage(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		got, err := dec.DecodeHeader(msg.Header.Get("Subject"))
		if err != nil || got != strings.TrimSpace(c.subject) {
			t.Errorf("subject round trip: %q -> %q (%v)", c.subject, got, err)
		}
		from, err := msg.Header.AddressList("From")
		if err != nil || len(from) != 1 || from[0].Name != c.name {
			t.Errorf("from round trip: %q -> %v (%v)", c.name, from, err)
		}
	}
	// No display name: bare address.
	s := buildSettings()
	s.FromName = ""
	raw, err := Build(s, Message{To: []string{"bob@example.com"}, Subject: "x", Text: "x"})
	if err != nil || !bytes.Contains(raw, []byte("From: noreply@entity-a.example.com\r\n")) {
		t.Errorf("bare from: %v\n%s", err, raw)
	}
}

func TestBuildRejects(t *testing.T) {
	base := func() Message {
		return Message{To: []string{"bob@example.com"}, Subject: "s", Text: "t", HTML: "<p>h</p>"}
	}
	img := InlinePart{ContentID: "qr@transteira", ContentType: "image/png", Data: []byte{1}}
	many := make([]string, maxRecipients+1)
	for i := range many {
		many[i] = fmt.Sprintf("r%d@example.com", i)
	}
	mutations := map[string]func(*Message){
		"no recipient":      func(m *Message) { m.To = nil },
		"too many":          func(m *Message) { m.To = many },
		"bad recipient":     func(m *Message) { m.To = []string{"bob@example.com\r\nBcc: eve@example.com"} },
		"named recipient":   func(m *Message) { m.To = []string{"Bob <bob@example.com>"} },
		"subject crlf":      func(m *Message) { m.Subject = "Hi\r\nBcc: eve@example.com" },
		"subject lf":        func(m *Message) { m.Subject = "Hi\nX-Evil: 1" },
		"subject cr":        func(m *Message) { m.Subject = "Hi\rX-Evil: 1" },
		"subject tab":       func(m *Message) { m.Subject = "Hi\tthere" },
		"subject nul":       func(m *Message) { m.Subject = "Hi\x00" },
		"subject u2028":     func(m *Message) { m.Subject = "Hi there" },
		"subject utf8":      func(m *Message) { m.Subject = "\xff" },
		"subject empty":     func(m *Message) { m.Subject = "  " },
		"subject long":      func(m *Message) { m.Subject = strings.Repeat("é", maxSubjectLen+1) },
		"no text":           func(m *Message) { m.Text = "" },
		"text big":          func(m *Message) { m.Text = strings.Repeat("a", maxBodyLen+1) },
		"html big":          func(m *Message) { m.HTML = strings.Repeat("a", maxBodyLen+1) },
		"text utf8":         func(m *Message) { m.Text = "\xff" },
		"html utf8":         func(m *Message) { m.HTML = "\xfe" },
		"inline no html":    func(m *Message) { m.HTML = ""; m.Inline = []InlinePart{img} },
		"too many inline":   func(m *Message) { m.Inline = make([]InlinePart, maxInlineParts+1) },
		"duplicate cid":     func(m *Message) { m.Inline = []InlinePart{img, img} },
		"cid crlf":          func(m *Message) { p := img; p.ContentID = "a\r\nb"; m.Inline = []InlinePart{p} },
		"cid brackets":      func(m *Message) { p := img; p.ContentID = "<qr@x>"; m.Inline = []InlinePart{p} },
		"cid empty":         func(m *Message) { p := img; p.ContentID = ""; m.Inline = []InlinePart{p} },
		"cid two at":        func(m *Message) { p := img; p.ContentID = "a@b@c"; m.Inline = []InlinePart{p} },
		"cid empty right":   func(m *Message) { p := img; p.ContentID = "a@"; m.Inline = []InlinePart{p} },
		"cid long":          func(m *Message) { p := img; p.ContentID = strings.Repeat("a", 101); m.Inline = []InlinePart{p} },
		"type text":         func(m *Message) { p := img; p.ContentType = "text/html"; m.Inline = []InlinePart{p} },
		"type params":       func(m *Message) { p := img; p.ContentType = "image/png; name=x"; m.Inline = []InlinePart{p} },
		"type crlf":         func(m *Message) { p := img; p.ContentType = "image/png\r\nX: y"; m.Inline = []InlinePart{p} },
		"type garbage":      func(m *Message) { p := img; p.ContentType = "///"; m.Inline = []InlinePart{p} },
		"filename quote":    func(m *Message) { p := img; p.Filename = `a".png`; m.Inline = []InlinePart{p} },
		"filename crlf":     func(m *Message) { p := img; p.Filename = "a\r\n.png"; m.Inline = []InlinePart{p} },
		"filename long":     func(m *Message) { p := img; p.Filename = strings.Repeat("a", 101); m.Inline = []InlinePart{p} },
		"inline empty data": func(m *Message) { p := img; p.Data = nil; m.Inline = []InlinePart{p} },
		"inline big data":   func(m *Message) { p := img; p.Data = make([]byte, maxInlineSize+1); m.Inline = []InlinePart{p} },
	}
	for name, mut := range mutations {
		m := base()
		mut(&m)
		if _, err := Build(buildSettings(), m); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := Build(Settings{}, base()); !errors.Is(err, ErrInvalidSettings) {
		t.Errorf("settings: err = %v", err)
	}
}

// allowedHeaders lists every top-level header Build may write.
var allowedHeaders = map[string]bool{
	"From": true, "To": true, "Subject": true, "Date": true, "Message-Id": true, "Mime-Version": true,
	"Content-Language": true, "Auto-Submitted": true, "Content-Type": true, "Content-Transfer-Encoding": true,
}

func FuzzBuildHeaders(f *testing.F) {
	f.Add("Hello", "Entity A", "bob@example.com")
	f.Add("Hi\r\nBcc: eve@example.com", "A\r\nX: y", "bob@example.com\r\nBcc: eve@example.com")
	f.Add("=?utf-8?q?x?=", `"quoted" \ name`, "Bob <bob@example.com>")
	f.Add("Votre code de vérification", "Entité A", "a@b.example.com")
	f.Add(strings.Repeat("é", 120), strings.Repeat("ü", 60), "x@y.zz")
	f.Fuzz(func(t *testing.T, subject, name, addr string) {
		s := buildSettings()
		s.FromName = name
		raw, err := Build(s, Message{To: []string{addr}, Subject: subject, Text: "body"})
		if err != nil {
			return
		}
		checkCRLF(t, raw)
		msg, err := netmail.ReadMessage(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("unparsable message: %v\n%q", err, raw)
		}
		for k, v := range msg.Header {
			if !allowedHeaders[k] || len(v) != 1 {
				t.Fatalf("unexpected header %q = %q", k, v)
			}
		}
		got, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
		if err != nil || got != strings.TrimSpace(subject) {
			t.Fatalf("subject %q -> %q (%v)", subject, got, err)
		}
		to, err := msg.Header.AddressList("To")
		want, _ := ParseAddress(addr)
		if err != nil || len(to) != 1 || to[0].Address != want {
			t.Fatalf("to %q -> %v (%v)", addr, to, err)
		}
		from, err := msg.Header.AddressList("From")
		if err != nil || len(from) != 1 || from[0].Name != name || from[0].Address != s.FromAddress {
			t.Fatalf("from %q -> %v (%v)", name, from, err)
		}
	})
}
