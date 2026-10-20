package mail

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"
)

// testCert is a self-signed certificate for 127.0.0.1 and localhost,
// generated once per test binary.
var testCert = sync.OnceValues(func() (tls.Certificate, *x509.CertPool) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake smtp"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
})

// received is one message accepted by the fake server.
type received struct {
	from   string
	to     []string
	data   []byte
	tls    bool
	authed bool
}

// fakeSMTP is a minimal in-memory SMTP server for tests.
type fakeSMTP struct {
	t             *testing.T
	ln            net.Listener
	implicitTLS   bool
	offerStartTLS bool
	user, pass    string // AUTH PLAIN offered when user != ""
	silent        bool   // accept the connection but never answer
	// replies overrides the reply to a verb (GREETING, EHLO, HELO, STARTTLS,
	// AUTH, MAIL, RCPT, DATA, DATAEND, QUIT). "close" closes the connection.
	replies map[string]string

	mu   sync.Mutex
	msgs []received
	wg   sync.WaitGroup
}

// startFake starts f on a loopback port and stops it at test cleanup.
func startFake(t *testing.T, f *fakeSMTP) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.t, f.ln = t, ln
	if f.replies == nil {
		f.replies = map[string]string{}
	}
	var conns sync.Map
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Store(c, true)
			f.wg.Add(1)
			go func() {
				defer f.wg.Done()
				f.serve(c)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		conns.Range(func(k, _ any) bool { _ = k.(net.Conn).Close(); return true })
		f.wg.Wait()
	})
	return f
}

// port returns the listening port.
func (f *fakeSMTP) port() int {
	return f.ln.Addr().(*net.TCPAddr).Port
}

// messages returns the accepted messages.
func (f *fakeSMTP) messages() []received {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]received(nil), f.msgs...)
}

// serverTLS is the server-side TLS configuration.
func serverTLS() *tls.Config {
	cert, _ := testCert()
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}

// reply sends the override for verb if any (reporting whether one was
// sent and whether the connection must close), else def.
func (f *fakeSMTP) reply(tp *textproto.Conn, verb, def string) (closeConn bool) {
	r, ok := f.replies[verb]
	if !ok {
		r = def
	}
	if r == "close" {
		return true
	}
	_ = tp.PrintfLine("%s", r)
	return false
}

// serve runs one SMTP session.
func (f *fakeSMTP) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	isTLS := false
	if f.implicitTLS {
		tc := tls.Server(c, serverTLS())
		if err := tc.Handshake(); err != nil {
			return
		}
		c, isTLS = tc, true
	}
	if f.silent {
		_, _ = c.Read(make([]byte, 1)) // blocks until the client gives up
		return
	}
	tp := textproto.NewConn(c)
	if f.reply(tp, "GREETING", "220 fake.example.com ESMTP") {
		return
	}
	var cur received
	authed := false
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		verb, arg, _ := strings.Cut(line, " ")
		verb = strings.ToUpper(verb)
		switch verb {
		case "EHLO", "HELO":
			if r, ok := f.replies[verb]; ok {
				_ = tp.PrintfLine("%s", r)
				continue
			}
			lines := []string{"fake.example.com"}
			if f.offerStartTLS && !isTLS {
				lines = append(lines, "STARTTLS")
			}
			if f.user != "" {
				lines = append(lines, "AUTH PLAIN")
			}
			lines = append(lines, "8BITMIME")
			for i, l := range lines {
				sep := "-"
				if i == len(lines)-1 {
					sep = " "
				}
				_ = tp.PrintfLine("250%s%s", sep, l)
			}
		case "STARTTLS":
			if f.reply(tp, verb, "220 go ahead") {
				return
			}
			if _, ok := f.replies[verb]; ok {
				continue
			}
			tc := tls.Server(c, serverTLS())
			if err := tc.Handshake(); err != nil {
				return
			}
			c, isTLS = tc, true
			tp = textproto.NewConn(c)
		case "AUTH":
			mech, resp, _ := strings.Cut(arg, " ")
			want := base64.StdEncoding.EncodeToString([]byte("\x00" + f.user + "\x00" + f.pass))
			if r, ok := f.replies[verb]; ok {
				_ = tp.PrintfLine("%s", r)
				continue
			}
			if strings.EqualFold(mech, "PLAIN") && resp == want {
				authed = true
				_ = tp.PrintfLine("235 2.7.0 authenticated")
			} else {
				_ = tp.PrintfLine("535 5.7.8 bad credentials")
			}
		case "MAIL":
			cur = received{from: strings.TrimSuffix(strings.TrimPrefix(strings.Fields(arg)[0], "FROM:<"), ">")}
			if f.reply(tp, verb, "250 ok") {
				return
			}
		case "RCPT":
			cur.to = append(cur.to, strings.TrimSuffix(strings.TrimPrefix(arg, "TO:<"), ">"))
			if f.reply(tp, verb, "250 ok") {
				return
			}
		case "DATA":
			if f.reply(tp, verb, "354 go ahead") {
				return
			}
			if _, ok := f.replies[verb]; ok {
				continue
			}
			data, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			cur.data = bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
			cur.tls, cur.authed = isTLS, authed
			f.mu.Lock()
			f.msgs = append(f.msgs, cur)
			f.mu.Unlock()
			if f.reply(tp, "DATAEND", "250 queued") {
				return
			}
		case "QUIT":
			f.reply(tp, verb, "221 bye")
			return
		case "RSET", "NOOP":
			_ = tp.PrintfLine("250 ok")
		default:
			_ = tp.PrintfLine("502 unknown")
		}
	}
}
