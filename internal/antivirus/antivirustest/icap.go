package antivirustest

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// InfectionHeader is the ICAP header the fake ICAP server sets on an
// infected content, and InfectionValue its value (c-icap style).
const (
	InfectionHeader = "X-Infection-Found"
	InfectionValue  = "Type=0; Resolution=2; Threat=" + EicarSignature + ";"
)

// ICAPMode selects how the fake ICAP server answers RESPMOD requests.
type ICAPMode int

// ICAP modes.
const (
	// ICAPModeScan answers 200 with InfectionHeader and a replacement page
	// when the content contains the EICAR string, 204 otherwise.
	ICAPModeScan ICAPMode = iota
	// ICAPModeNoContent always answers 204.
	ICAPModeNoContent
	// ICAPModeEcho answers 200 with the encapsulated response and the
	// content sent back unchanged.
	ICAPModeEcho
	// ICAPModeModified answers 200 like ICAPModeEcho, with the first byte
	// of the content changed (or one byte added to an empty content).
	ICAPModeModified
	// ICAPMode500 answers 500.
	ICAPMode500
	// ICAPMode503 answers 503.
	ICAPMode503
	// ICAPModeClose reads the request and closes the connection without
	// replying.
	ICAPModeClose
	// ICAPModeHang reads the request and never replies, until the server
	// stops.
	ICAPModeHang
	// ICAPModeRaw reads the request and writes the bytes given to SetRaw
	// (garbage or malformed replies).
	ICAPModeRaw
)

// ICAPRequest is one request as received by the fake ICAP server.
type ICAPRequest struct {
	// Method and URI are taken from the request line.
	Method, URI string
	// Header holds the ICAP headers.
	Header textproto.MIMEHeader
	// Encapsulated holds the encapsulated HTTP headers (req-hdr and
	// res-hdr), as received.
	Encapsulated []byte
	// Body is the de-chunked content received (preview included).
	Body []byte
	// Preview reports that the request had a Preview header, and IEOF
	// that the preview carried the whole content ("0; ieof").
	Preview, IEOF bool
	// Continued reports that the server answered 100 Continue.
	Continued bool
	// Complete reports that the whole request was received.
	Complete bool
}

// ICAPServer is a fake ICAP server listening on a local address. Its
// methods are safe for concurrent use. It keeps every request in memory and
// is meant for small test contents.
type ICAPServer struct {
	address string
	tlsCfg  *tls.Config

	mu            sync.Mutex
	ln            net.Listener
	conns         map[net.Conn]struct{}
	mode          ICAPMode
	raw           []byte
	preview       int
	ttl           int
	methods       string
	optionsStatus int
	early         bool
	requests      []ICAPRequest
	wg            sync.WaitGroup
}

// NewICAP starts a fake ICAP server on a random TCP port of 127.0.0.1, in
// cleartext. It advertises RESPMOD without preview. It is closed when the
// test ends.
func NewICAP(t testing.TB) *ICAPServer {
	t.Helper()
	return startICAP(t, nil)
}

// NewICAPTLS starts a fake ICAP server speaking TLS with cfg.
func NewICAPTLS(t testing.TB, cfg *tls.Config) *ICAPServer {
	t.Helper()
	return startICAP(t, cfg)
}

func startICAP(t testing.TB, cfg *tls.Config) *ICAPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("antivirustest: listen: %v", err)
	}
	s := &ICAPServer{
		address:       ln.Addr().String(),
		tlsCfg:        cfg,
		ln:            ln,
		conns:         make(map[net.Conn]struct{}),
		preview:       -1,
		ttl:           -1,
		methods:       "RESPMOD",
		optionsStatus: 200,
	}
	s.wg.Add(1)
	go s.accept(ln)
	t.Cleanup(s.Stop)
	return s
}

// Addr returns the listening address ("127.0.0.1:port").
func (s *ICAPServer) Addr() string { return s.address }

// URL returns the icap:// (or icaps:// with TLS) URL of the service path.
func (s *ICAPServer) URL(path string) string {
	scheme := "icap"
	if s.tlsCfg != nil {
		scheme = "icaps"
	}
	return scheme + "://" + s.address + path
}

// SetMode changes how the following RESPMOD requests are answered.
func (s *ICAPServer) SetMode(m ICAPMode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = m
}

// SetRaw sets the reply written in ICAPModeRaw.
func (s *ICAPServer) SetRaw(reply []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.raw = bytes.Clone(reply)
}

// SetPreview makes OPTIONS advertise a Preview of n bytes; a negative n
// removes the header (no preview).
func (s *ICAPServer) SetPreview(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preview = n
}

// SetOptionsTTL makes OPTIONS advertise an Options-TTL of n seconds; a
// negative n removes the header.
func (s *ICAPServer) SetOptionsTTL(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ttl = n
}

// SetOptions sets the status and the Methods header of OPTIONS replies
// (default 200 and "RESPMOD"; an empty methods removes the header).
func (s *ICAPServer) SetOptions(status int, methods string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.optionsStatus, s.methods = status, methods
}

// SetEarlyVerdict makes the server answer a preview that does not carry the
// whole content with its final verdict on the preview alone (ICAPModeScan
// rules), instead of 100 Continue.
func (s *ICAPServer) SetEarlyVerdict(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.early = on
}

// Requests returns a copy of the requests received so far (OPTIONS and
// RESPMOD), in the order they ended.
func (s *ICAPServer) Requests() []ICAPRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ICAPRequest, len(s.requests))
	for i, r := range s.requests {
		r.Header = textproto.MIMEHeader(cloneHeader(r.Header))
		r.Encapsulated = bytes.Clone(r.Encapsulated)
		r.Body = bytes.Clone(r.Body)
		out[i] = r
	}
	return out
}

// Count returns the number of requests received with method.
func (s *ICAPServer) Count(method string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.requests {
		if r.Method == method {
			n++
		}
	}
	return n
}

// Stop closes the listener and every open connection, and waits for the
// handlers to return. Stopping a stopped server does nothing.
func (s *ICAPServer) Stop() {
	s.mu.Lock()
	if s.ln != nil {
		_ = s.ln.Close()
		s.ln = nil
	}
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func cloneHeader(h textproto.MIMEHeader) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, v := range h {
		out[k] = append([]string(nil), v...)
	}
	return out
}

func (s *ICAPServer) accept(ln net.Listener) {
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if s.tlsCfg != nil {
			conn = tls.Server(conn, s.tlsCfg)
		}
		s.mu.Lock()
		if s.ln == nil {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() {
				_ = conn.Close()
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
			}()
			s.handle(conn)
		}()
	}
}

// handle serves one request.
func (s *ICAPServer) handle(conn net.Conn) {
	br := bufio.NewReader(conn)
	tp := textproto.NewReader(br)
	line, err := tp.ReadLine()
	if err != nil {
		return
	}
	method, rest, _ := strings.Cut(line, " ")
	uri, _, _ := strings.Cut(rest, " ")
	header, err := tp.ReadMIMEHeader()
	if err != nil {
		return
	}
	req := &ICAPRequest{Method: method, URI: uri, Header: header}
	// The request is recorded before the final reply is written, so that
	// a client that got its reply always finds it in Requests.
	record := sync.OnceFunc(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.requests = append(s.requests, *req)
	})
	defer record()
	switch method {
	case "OPTIONS":
		req.Complete = true
		record()
		s.options(conn)
	case "RESPMOD":
		s.respmod(conn, br, req, record)
	default:
		_, _ = io.WriteString(conn, "ICAP/1.0 405 Method Not Allowed\r\nEncapsulated: null-body=0\r\n\r\n")
	}
}

// options answers an OPTIONS request.
func (s *ICAPServer) options(conn net.Conn) {
	s.mu.Lock()
	status, methods, preview, ttl := s.optionsStatus, s.methods, s.preview, s.ttl
	s.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "ICAP/1.0 %d Status\r\nISTag: \"tt-1\"\r\nService: TransTeira fake ICAP\r\n", status)
	if methods != "" {
		fmt.Fprintf(&b, "Methods: %s\r\n", methods)
	}
	if preview >= 0 {
		fmt.Fprintf(&b, "Preview: %d\r\nTransfer-Preview: *\r\n", preview)
	}
	if ttl >= 0 {
		fmt.Fprintf(&b, "Options-TTL: %d\r\n", ttl)
	}
	b.WriteString("Allow: 204\r\nEncapsulated: null-body=0\r\n\r\n")
	_, _ = io.WriteString(conn, b.String())
}

// respmod serves a RESPMOD request.
func (s *ICAPServer) respmod(conn net.Conn, br *bufio.Reader, req *ICAPRequest, record func()) {
	s.mu.Lock()
	mode, raw, early := s.mode, s.raw, s.early
	s.mu.Unlock()

	bodyAt, err := bodyOffset(req.Header.Get("Encapsulated"))
	if err != nil {
		return
	}
	req.Encapsulated = make([]byte, bodyAt)
	if _, err := io.ReadFull(br, req.Encapsulated); err != nil {
		return
	}
	req.Preview = req.Header.Get("Preview") != ""
	ieof, err := readChunks(br, &req.Body)
	if err != nil {
		return
	}
	if req.Preview {
		req.IEOF = ieof
		if !ieof {
			if early {
				record()
				s.verdict(conn, ICAPModeScan, req)
				return
			}
			req.Continued = true
			if _, err := io.WriteString(conn, "ICAP/1.0 100 Continue\r\n\r\n"); err != nil {
				return
			}
			if _, err := readChunks(br, &req.Body); err != nil {
				return
			}
		}
	}
	req.Complete = true
	record()
	switch mode {
	case ICAPModeClose:
	case ICAPModeHang:
		_, _ = io.Copy(io.Discard, br)
	case ICAPModeRaw:
		_, _ = conn.Write(raw)
	default:
		s.verdict(conn, mode, req)
	}
}

// verdict writes the reply of mode to req.
func (s *ICAPServer) verdict(conn net.Conn, mode ICAPMode, req *ICAPRequest) {
	switch mode {
	case ICAPModeScan:
		if !bytes.Contains(req.Body, EICAR()) {
			_, _ = io.WriteString(conn, "ICAP/1.0 204 No Content\r\nISTag: \"tt-1\"\r\n\r\n")
			return
		}
		page := "<html><body>Virus found</body></html>"
		res := fmt.Sprintf("HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n", len(page))
		_, _ = fmt.Fprintf(conn, "ICAP/1.0 200 OK\r\nISTag: \"tt-1\"\r\n%s: %s\r\nEncapsulated: res-hdr=0, res-body=%d\r\n\r\n%s%x\r\n%s\r\n0\r\n\r\n",
			InfectionHeader, InfectionValue, len(res), res, len(page), page)
	case ICAPModeNoContent:
		_, _ = io.WriteString(conn, "ICAP/1.0 204 No Content\r\nISTag: \"tt-1\"\r\nEncapsulated: null-body=0\r\n\r\n")
	case ICAPModeEcho, ICAPModeModified:
		body := bytes.Clone(req.Body)
		if mode == ICAPModeModified {
			if len(body) == 0 {
				body = []byte{'x'}
			} else {
				body[0] ^= 0xff
			}
		}
		res := resHeader(req.Encapsulated)
		var b bytes.Buffer
		fmt.Fprintf(&b, "ICAP/1.0 200 OK\r\nISTag: \"tt-1\"\r\nEncapsulated: res-hdr=0, res-body=%d\r\n\r\n", len(res))
		b.Write(res)
		for len(body) > 0 {
			n := min(len(body), 8<<10)
			fmt.Fprintf(&b, "%x\r\n", n)
			b.Write(body[:n])
			b.WriteString("\r\n")
			body = body[n:]
		}
		b.WriteString("0\r\n\r\n")
		_, _ = conn.Write(b.Bytes())
	case ICAPMode500:
		_, _ = io.WriteString(conn, "ICAP/1.0 500 Server Error\r\nEncapsulated: null-body=0\r\n\r\n")
	case ICAPMode503:
		_, _ = io.WriteString(conn, "ICAP/1.0 503 Service Overloaded\r\nEncapsulated: null-body=0\r\n\r\n")
	}
}

// resHeader returns the res-hdr part of the encapsulated headers received
// (everything after the first empty line, which ends req-hdr).
func resHeader(enc []byte) []byte {
	if i := bytes.Index(enc, []byte("\r\n\r\n")); i >= 0 && i+4 < len(enc) {
		return bytes.Clone(enc[i+4:])
	}
	return []byte("HTTP/1.1 200 OK\r\n\r\n")
}

// bodyOffset returns the offset of the body entry of an Encapsulated value.
func bodyOffset(v string) (int, error) {
	for _, f := range strings.Split(v, ",") {
		name, off, _ := strings.Cut(strings.TrimSpace(f), "=")
		if strings.HasSuffix(name, "-body") {
			return strconv.Atoi(off)
		}
	}
	return 0, errors.New("no body entry")
}

// readChunks reads chunks up to the last one, appending their data to body,
// and reports whether the last chunk carried the ieof extension.
func readChunks(br *bufio.Reader, body *[]byte) (bool, error) {
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return false, err
		}
		line = strings.TrimRight(line, "\r\n")
		digits, ext, _ := strings.Cut(line, ";")
		n, err := strconv.ParseInt(strings.TrimSpace(digits), 16, 64)
		if err != nil || n < 0 || n > 16<<20 {
			return false, errors.New("bad chunk size")
		}
		if n == 0 {
			if _, err := br.ReadString('\n'); err != nil {
				return false, err
			}
			return strings.TrimSpace(ext) == "ieof", nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return false, err
		}
		*body = append(*body, buf[:n]...)
	}
}

// TLSConfig generates, at run time, a test CA and a server certificate
// signed by it for 127.0.0.1 and localhost. It returns the server TLS
// configuration and the PEM of the CA.
func TLSConfig(t testing.TB) (*tls.Config, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TransTeira test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
	return cfg, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}
