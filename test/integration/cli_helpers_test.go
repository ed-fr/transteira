package integration_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/cli/client"
)

// Helpers of the command-line client tests (V2 step 9; internal/cli/...).
// The client is HTTPS-only: a TLS front in front of the in-process server
// keeps the Host of the tenant, sets the client IP and can cut a PATCH.

// errCut is the error that ends a PATCH body the front was told to cut.
var errCut = errors.New("front: connection cut")

// cutBody ends the body of a request with errCut after left bytes.
type cutBody struct {
	r    io.ReadCloser
	left int64
	cut  *atomic.Bool
}

func (b *cutBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		b.cut.Store(true)
		return 0, errCut
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.r.Read(p)
	b.left -= int64(n)
	return n, err
}

func (b *cutBody) Close() error { return b.r.Close() }

// cliFront is a TLS reverse proxy to the server under test.
type cliFront struct {
	srv  *httptest.Server
	pool *x509.CertPool
	ip   string

	mu       sync.Mutex
	requests []string // "METHOD path"
	created  []string // transfer identifiers returned by createTransfer

	// cutAfter, when positive, cuts the next PATCH after that many body
	// bytes and then resets itself.
	cutAfter atomic.Int64
	cutFlag  atomic.Bool
}

// frontCert returns a certificate for the tenant hosts and *.localhost.
func frontCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "transteira cli test front"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{hostA, hostB, "*.localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// startCLIFront starts the TLS front of s; clientIP is sent as
// X-Forwarded-For. The front never buffers.
func startCLIFront(t *testing.T, s *server, clientIP string) *cliFront {
	t.Helper()
	cert, pool := frontCert(t)
	f := &cliFront{pool: pool, ip: clientIP}
	proxy := &httputil.ReverseProxy{
		FlushInterval: -1,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(&url.URL{Scheme: "http", Host: s.addr})
			r.Out.Host = r.In.Host
			r.Out.Header.Set(hdrXFF, clientIP)
		},
		ModifyResponse: func(resp *http.Response) error {
			if resp.Request.Method == http.MethodPost && resp.Request.URL.Path == pathTransfers && resp.StatusCode == http.StatusCreated {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return err
				}
				_ = resp.Body.Close()
				var tr struct {
					ID string `json:"id"`
				}
				if json.Unmarshal(body, &tr) == nil {
					f.mu.Lock()
					f.created = append(f.created, tr.ID)
					f.mu.Unlock()
				}
				resp.Body = io.NopCloser(bytes.NewReader(body))
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			if f.cutFlag.CompareAndSwap(true, false) || errors.Is(err, errCut) {
				if conn, _, herr := http.NewResponseController(w).Hijack(); herr == nil {
					_ = conn.Close()
					return
				}
			}
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		if r.Method == http.MethodPatch {
			if n := f.cutAfter.Load(); n > 0 && f.cutAfter.CompareAndSwap(n, 0) {
				r.Body = &cutBody{r: r.Body, left: n, cut: &f.cutFlag}
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

// requestCount returns the number of requests the front received.
func (f *cliFront) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// createdIDs returns the identifiers of the transfers created through the
// front.
func (f *cliFront) createdIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.created...)
}

// newClient returns a command-line client for host through the front.
func (f *cliFront) newClient(t *testing.T, host, token, sender string) *client.Client {
	t.Helper()
	addr := f.srv.Listener.Addr().String()
	c, err := client.New(client.Config{URL: "https://" + host, Token: token, Sender: sender},
		client.WithRootCAs(f.pool),
		client.WithDialContext(func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}),
		// No real pause: the retries are deterministic and instantaneous.
		client.WithSleep(func(ctx context.Context, _ time.Duration) error { return ctx.Err() }),
	)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c
}

// writeTree writes the files (slash path to content) under dir.
func writeTree(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	for rel, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
