package antivirus

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"
	"unicode/utf8"

	"github.com/ed-fr/transteira/internal/antivirus/antivirustest"
)

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func scanClient(srv *antivirustest.Server, opts ...Option) *Client {
	return NewClient(srv.Network(), srv.Addr(), opts...)
}

func scanBytes(t *testing.T, c *Client, data []byte) (Result, error) {
	t.Helper()
	return c.Scan(context.Background(), bytes.NewReader(data), int64(len(data)))
}

func TestVerdictString(t *testing.T) {
	for v, want := range map[Verdict]string{
		Clean: "clean", Infected: "infected", TooLarge: "too_large", Unscannable: "unscannable",
		0: "verdict(0)", 9: "verdict(9)",
	} {
		if got := v.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", int(v), got, want)
		}
	}
}

func TestScanOptions(t *testing.T) {
	c := NewClient("tcp", "x")
	if c.maxScanBytes != DefaultMaxScanBytes || c.scanTimeout != DefaultScanTimeout || c.idleTimeout != DefaultIdleTimeout {
		t.Fatalf("defaults = %+v", c)
	}
	c = NewClient("tcp", "x", WithMaxScanBytes(0), WithMaxScanBytes(-1), WithScanTimeout(0), WithScanTimeout(-1),
		WithIdleTimeout(0), WithIdleTimeout(-1))
	if c.maxScanBytes != DefaultMaxScanBytes || c.scanTimeout != DefaultScanTimeout || c.idleTimeout != DefaultIdleTimeout {
		t.Fatalf("ignored options changed client: %+v", c)
	}
	c = NewClient("tcp", "x", WithMaxScanBytes(5), WithScanTimeout(time.Second), WithIdleTimeout(time.Millisecond))
	if c.maxScanBytes != 5 || c.scanTimeout != time.Second || c.idleTimeout != time.Millisecond {
		t.Fatalf("options = %+v", c)
	}
}

func TestScanVerdicts(t *testing.T) {
	srv := antivirustest.New(t)
	c := scanClient(srv)

	// Clean, several chunks with a short last one.
	data := randomBytes(t, 3*chunkSize+1234)
	res, err := scanBytes(t, c, data)
	if err != nil || res != (Result{Verdict: Clean}) {
		t.Fatalf("clean: %+v, %v", res, err)
	}
	scans := srv.Scans()
	if len(scans) != 1 || !scans[0].Complete || !bytes.Equal(scans[0].Data, data) {
		t.Fatalf("server received %d scans, complete %v, equal %v", len(scans), scans[0].Complete, bytes.Equal(scans[0].Data, data))
	}
	if want := []int{chunkSize, chunkSize, chunkSize, 1234}; !equalInts(scans[0].Chunks, want) {
		t.Fatalf("chunks = %v, want %v", scans[0].Chunks, want)
	}

	// Infected: the EICAR string straddles two chunks.
	infected := append(randomBytes(t, chunkSize-10), antivirustest.EICAR()...)
	infected = append(infected, randomBytes(t, 100)...)
	res, err = scanBytes(t, c, infected)
	if err != nil || res != (Result{Verdict: Infected, Signature: antivirustest.EicarSignature}) {
		t.Fatalf("infected: %+v, %v", res, err)
	}

	// Empty content: only the end marker.
	res, err = scanBytes(t, c, nil)
	if err != nil || res.Verdict != Clean {
		t.Fatalf("empty: %+v, %v", res, err)
	}
	if last := srv.Scans()[2]; len(last.Chunks) != 0 || !last.Complete {
		t.Fatalf("empty scan = %+v", last)
	}

	// clamd size limit.
	srv.SetSizeLimit(chunkSize)
	res, err = scanBytes(t, c, randomBytes(t, 2*chunkSize))
	if err != nil || res != (Result{Verdict: TooLarge, Detail: DetailStreamLimit}) {
		t.Fatalf("size limit: %+v, %v", res, err)
	}

	// Partial analyses reported by heuristic signatures.
	srv.SetSizeLimit(0)
	srv.SetMode(antivirustest.ModeLimitsExceeded)
	res, err = scanBytes(t, c, data)
	if err != nil || res != (Result{Verdict: TooLarge, Detail: antivirustest.LimitsExceededSignature}) {
		t.Fatalf("limits exceeded: %+v, %v", res, err)
	}
	srv.SetMode(antivirustest.ModeEncrypted)
	res, err = scanBytes(t, c, data)
	if err != nil || res != (Result{Verdict: Unscannable, Detail: antivirustest.EncryptedSignature}) {
		t.Fatalf("encrypted: %+v, %v", res, err)
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestScanSizePrecheck(t *testing.T) {
	srv := antivirustest.New(t)
	c := scanClient(srv, WithMaxScanBytes(100))

	res, err := c.Scan(context.Background(), iotest.ErrReader(errors.New("must not be read")), 101)
	if err != nil || res != (Result{Verdict: TooLarge, Detail: DetailClientLimit}) {
		t.Fatalf("over limit: %+v, %v", res, err)
	}
	if n := len(srv.Scans()); n != 0 {
		t.Fatalf("clamd contacted %d times", n)
	}
	res, err = scanBytes(t, c, randomBytes(t, 100))
	if err != nil || res.Verdict != Clean {
		t.Fatalf("at limit: %+v, %v", res, err)
	}
	if _, err := c.Scan(context.Background(), bytes.NewReader(nil), -1); !errors.Is(err, ErrSource) {
		t.Fatalf("negative size = %v", err)
	}
}

// probeErrReader yields data, then fails with err instead of io.EOF.
type probeErrReader struct {
	data []byte
	err  error
}

func (r *probeErrReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestScanSourceErrors(t *testing.T) {
	srv := antivirustest.New(t)
	c := scanClient(srv)
	errRead := errors.New("decrypt failed")
	data := randomBytes(t, chunkSize+10)
	tests := []struct {
		name string
		r    io.Reader
		size int64
		want error
	}{
		{"shorter", bytes.NewReader(data), int64(len(data)) + 1, nil},
		{"shorter at chunk boundary", bytes.NewReader(data[:chunkSize]), chunkSize + 1, nil},
		{"longer", bytes.NewReader(data), int64(len(data)) - 1, nil},
		{"read error", io.MultiReader(bytes.NewReader(data[:100]), iotest.ErrReader(errRead)), int64(len(data)), errRead},
		{"error after the content", &probeErrReader{data: data, err: errRead}, int64(len(data)), errRead},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.Scan(context.Background(), tt.r, tt.size)
			if !errors.Is(err, ErrSource) || errors.Is(err, ErrUnavailable) || errors.Is(err, ErrProtocol) {
				t.Fatalf("Scan = %v, want only ErrSource", err)
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("Scan = %v, want %v", err, tt.want)
			}
		})
	}
}

// rawClamd answers every INSTREAM with answer once the stream ended.
func rawClamd(t *testing.T, answer string) string {
	t.Helper()
	ln := tcpListener(t)
	fakeClamd(t, ln, func(conn net.Conn) {
		_, _ = io.ReadFull(conn, make([]byte, len(instreamCommand)))
		_, _ = io.ReadFull(conn, make([]byte, 4)) // empty stream: end marker
		_, _ = conn.Write([]byte(answer))
	})
	return ln.Addr().String()
}

func TestScanProtocolErrors(t *testing.T) {
	tests := []struct {
		name, answer string
	}{
		{"unknown reply", "stream: Can't allocate memory ERROR\x00"},
		{"missing terminator", "stream: OK"},
		{"too long", strings.Repeat("A", maxScanReplyLen+10)},
		{"empty signature", "stream:  FOUND\x00"},
		{"hidden-only signature", "stream: \x01\xe2\x80\x8b FOUND\x00"},
		{"ok with suffix", "stream: OK \x00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := rawClamd(t, tt.answer)
			_, err := NewClient("tcp", addr).Scan(context.Background(), bytes.NewReader(nil), 0)
			if !errors.Is(err, ErrProtocol) || errors.Is(err, ErrUnavailable) {
				t.Fatalf("Scan = %v, want ErrProtocol", err)
			}
		})
	}

	srv := antivirustest.New(t)
	srv.SetMode(antivirustest.ModeGarbage)
	if _, err := scanBytes(t, scanClient(srv), []byte("x")); !errors.Is(err, ErrProtocol) {
		t.Fatalf("garbage = %v", err)
	}
}

func TestParseScanReplySignature(t *testing.T) {
	long := strings.Repeat("é", MaxSignatureLen) // 2 bytes per rune
	tests := []struct {
		name, reply, want string
	}{
		{"plain", "stream: Win.Test.EICAR_HDB-1 FOUND", "Win.Test.EICAR_HDB-1"},
		{"controls stripped", "stream: Bad\x1b[31m\nSig\t\x7f\xe2\x80\xae FOUND", "Bad[31mSig"},
		{"invalid utf8", "stream: A\xffB FOUND", "A�B"},
		{"bounded", "stream: " + long + " FOUND", long[:MaxSignatureLen]},
		{"bounded on rune boundary", "stream: x" + long + " FOUND", "x" + long[:MaxSignatureLen-2]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := parseScanReply([]byte(tt.reply))
			if err != nil || res.Verdict != Infected || res.Signature != tt.want {
				t.Fatalf("parse = %+v, %v, want %q", res, err, tt.want)
			}
			if len(res.Signature) > MaxSignatureLen || !utf8.ValidString(res.Signature) {
				t.Fatalf("signature not bounded or invalid: %q", res.Signature)
			}
		})
	}
}

func assertUnavailable(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrProtocol) || errors.Is(err, ErrSource) || errors.Is(err, ErrTimeout) {
		t.Fatalf("Scan = %v, want only ErrUnavailable", err)
	}
}

// assertLost checks an ErrUnavailable after a successful dial.
func assertLost(t *testing.T, err error) {
	t.Helper()
	assertUnavailable(t, err)
	if !errors.Is(err, ErrConnectionLost) {
		t.Fatalf("Scan = %v, want ErrConnectionLost", err)
	}
}

// assertNotLost checks an ErrUnavailable without a lost connection (dial
// failure, cancellation).
func assertNotLost(t *testing.T, err error) {
	t.Helper()
	assertUnavailable(t, err)
	if errors.Is(err, ErrConnectionLost) {
		t.Fatalf("Scan = %v, want no ErrConnectionLost", err)
	}
}

func assertTimeout(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrTimeout) || errors.Is(err, ErrUnavailable) || errors.Is(err, ErrProtocol) || errors.Is(err, ErrSource) {
		t.Fatalf("Scan = %v, want only ErrTimeout", err)
	}
	var nerr net.Error
	if !errors.As(err, &nerr) || !nerr.Timeout() {
		t.Fatalf("Scan = %v, want a timeout", err)
	}
}

func TestScanStopRestart(t *testing.T) {
	srv := antivirustest.New(t)
	c := scanClient(srv, WithScanTimeout(5*time.Second))
	data := randomBytes(t, 1000)

	srv.Stop()
	_, err := scanBytes(t, c, data)
	assertNotLost(t, err)

	srv.Restart(t)
	if res, err := scanBytes(t, c, data); err != nil || res.Verdict != Clean {
		t.Fatalf("after restart: %+v, %v", res, err)
	}
}

func TestScanCloseMidStream(t *testing.T) {
	srv := antivirustest.New(t)
	srv.SetMode(antivirustest.ModeCloseMidStream)
	c := scanClient(srv, WithScanTimeout(10*time.Second))
	for _, n := range []int{0, 10, 4 * chunkSize} {
		_, err := scanBytes(t, c, randomBytes(t, n))
		assertLost(t, err)
	}
}

func TestScanOverallTimeout(t *testing.T) {
	srv := antivirustest.New(t)
	srv.SetMode(antivirustest.ModeHang)
	c := scanClient(srv, WithScanTimeout(200*time.Millisecond))
	start := time.Now()
	_, err := scanBytes(t, c, randomBytes(t, 1000))
	assertTimeout(t, err)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Scan took %v", d)
	}
}

// pipeClamd returns a dialer connecting to an in-memory clamd served by
// handle (net.Pipe is unbuffered: a write blocks until the peer reads it).
func pipeClamd(t *testing.T, handle func(net.Conn)) DialFunc {
	t.Helper()
	return func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })
		go handle(server)
		return client, nil
	}
}

// slowClamd reads the stream with a pause before each read, then answers OK.
func slowClamd(pause time.Duration) func(net.Conn) {
	return func(conn net.Conn) {
		buf := make([]byte, 2*chunkSize)
		var total int
		for {
			time.Sleep(pause)
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			total += n
			if total >= len(instreamCommand)+4 && bytes.HasSuffix(buf[:n], endOfStream) {
				_, _ = conn.Write([]byte("stream: OK\x00"))
				return
			}
		}
	}
}

func TestScanIdleTimeout(t *testing.T) {
	never := func(net.Conn) {}
	c := NewClient("pipe", "x", WithDialer(pipeClamd(t, never)), WithIdleTimeout(100*time.Millisecond))
	start := time.Now()
	_, err := scanBytes(t, c, randomBytes(t, 10))
	assertTimeout(t, err)
	if d := time.Since(start); d > DefaultIdleTimeout/2 {
		t.Fatalf("Scan took %v", d)
	}
}

func TestScanFlowingStreamOutlivesIdleTimeout(t *testing.T) {
	// 8 chunks at 40 ms each take longer than the idle timeout, but every
	// write progresses within it.
	c := NewClient("pipe", "x", WithDialer(pipeClamd(t, slowClamd(40*time.Millisecond))),
		WithIdleTimeout(300*time.Millisecond))
	start := time.Now()
	res, err := scanBytes(t, c, randomBytes(t, 8*chunkSize))
	if err != nil || res.Verdict != Clean {
		t.Fatalf("Scan = %+v, %v", res, err)
	}
	if d := time.Since(start); d < 300*time.Millisecond {
		t.Fatalf("Scan took %v, the test does not exceed the idle timeout", d)
	}
}

func TestScanOverallTimeoutCapsFlowingStream(t *testing.T) {
	c := NewClient("pipe", "x", WithDialer(pipeClamd(t, slowClamd(40*time.Millisecond))),
		WithIdleTimeout(time.Minute), WithScanTimeout(200*time.Millisecond))
	_, err := scanBytes(t, c, randomBytes(t, 50*chunkSize))
	assertTimeout(t, err)
}

func TestScanContextCanceled(t *testing.T) {
	t.Run("before dial", func(t *testing.T) {
		srv := antivirustest.New(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := scanClient(srv).Scan(ctx, bytes.NewReader(nil), 0)
		assertUnavailable(t, err)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Scan = %v, want context.Canceled", err)
		}
	})
	t.Run("during write", func(t *testing.T) {
		started := make(chan struct{})
		c := NewClient("pipe", "x", WithDialer(pipeClamd(t, func(net.Conn) { close(started) })))
		ctx, cancel := context.WithCancel(context.Background())
		go func() { <-started; time.Sleep(50 * time.Millisecond); cancel() }()
		_, err := c.Scan(ctx, bytes.NewReader(make([]byte, 10)), 10)
		assertUnavailable(t, err)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Scan = %v, want context.Canceled", err)
		}
	})
	t.Run("waiting for the reply", func(t *testing.T) {
		srv := antivirustest.New(t)
		srv.SetMode(antivirustest.ModeHang)
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		_, err := scanClient(srv).Scan(ctx, bytes.NewReader(make([]byte, 10)), 10)
		assertUnavailable(t, err)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Scan = %v, want context.DeadlineExceeded", err)
		}
	})
}

func TestScanUnixSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "tt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	srv := antivirustest.NewUnix(t, filepath.Join(dir, "clamd.sock"))
	if srv.Network() != "unix" {
		t.Fatalf("network = %q", srv.Network())
	}
	res, err := scanBytes(t, scanClient(srv), antivirustest.EICAR())
	if err != nil || res.Verdict != Infected {
		t.Fatalf("Scan = %+v, %v", res, err)
	}
}

// scanConnStub is a net.Conn whose writes fail after a number of calls and
// whose deadline fails after a number of calls.
type scanConnStub struct {
	net.Conn
	writes, deadlines         int // calls before failing; negative never fails
	writeErr, deadlineErr     error
	replyData                 string
	writeCalls, deadlineCalls int
}

func (c *scanConnStub) SetDeadline(time.Time) error {
	c.deadlineCalls++
	if c.deadlines >= 0 && c.deadlineCalls > c.deadlines {
		return c.deadlineErr
	}
	return nil
}

func (c *scanConnStub) Write(p []byte) (int, error) {
	c.writeCalls++
	if c.writes >= 0 && c.writeCalls > c.writes {
		return 0, c.writeErr
	}
	return len(p), nil
}

func (c *scanConnStub) Read(p []byte) (int, error) {
	if c.replyData == "" {
		return 0, io.EOF
	}
	n := copy(p, c.replyData)
	c.replyData = c.replyData[n:]
	return n, nil
}

func (c *scanConnStub) Close() error { return nil }

func TestScanConnFailures(t *testing.T) {
	errFake := errors.New("fake")
	data := make([]byte, 2*chunkSize)
	tests := []struct {
		name string
		conn *scanConnStub
		want Result
	}{
		{"reset with size limit reply", &scanConnStub{writes: 1, deadlines: -1, writeErr: errFake, replyData: sizeLimitReply + "\x00"}, Result{Verdict: TooLarge, Detail: DetailStreamLimit}},
		{"reset with ok reply is not trusted", &scanConnStub{writes: 1, deadlines: -1, writeErr: errFake, replyData: okReply + "\x00"}, Result{}},
		{"reset without reply", &scanConnStub{writes: 0, deadlines: -1, writeErr: errFake}, Result{}},
		{"reset with garbage", &scanConnStub{writes: 2, deadlines: -1, writeErr: errFake, replyData: "zz\x00"}, Result{}},
		{"set deadline on write", &scanConnStub{writes: -1, deadlines: 0, deadlineErr: errFake}, Result{}},
		{"set deadline on read", &scanConnStub{writes: -1, deadlines: 4, deadlineErr: errFake, replyData: okReply + "\x00"}, Result{}},
		{"closed without reply", &scanConnStub{writes: -1, deadlines: -1}, Result{}},
		{"end marker write", &scanConnStub{writes: 3, deadlines: -1, writeErr: errFake}, Result{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dial := func(context.Context, string, string) (net.Conn, error) { return tt.conn, nil }
			res, err := NewClient("tcp", "x", WithDialer(dial)).Scan(context.Background(), bytes.NewReader(data), int64(len(data)))
			if tt.want.Verdict != 0 {
				if err != nil || res != tt.want {
					t.Fatalf("Scan = %+v, %v, want %+v", res, err, tt.want)
				}
				return
			}
			assertLost(t, err)
			if tt.conn.writeErr != nil && tt.conn.deadlineErr == nil && !errors.Is(err, errFake) {
				t.Fatalf("Scan = %v, want %v", err, errFake)
			}
		})
	}
}

func TestScanDialError(t *testing.T) {
	errFake := errors.New("refused")
	dial := func(context.Context, string, string) (net.Conn, error) { return nil, errFake }
	_, err := NewClient("tcp", "x", WithDialer(dial)).Scan(context.Background(), bytes.NewReader(nil), 0)
	assertNotLost(t, err)
	if !errors.Is(err, errFake) {
		t.Fatalf("Scan = %v, want %v", err, errFake)
	}
}

// TestScanLive runs against a real clamd when TT_TEST_CLAMAV_ADDR is set
// (for example "127.0.0.1:3310").
func TestScanLive(t *testing.T) {
	addr := os.Getenv("TT_TEST_CLAMAV_ADDR")
	if addr == "" {
		t.Skip("TT_TEST_CLAMAV_ADDR not set")
	}
	c := NewClient("tcp", addr, WithScanTimeout(time.Minute))
	if res, err := scanBytes(t, c, randomBytes(t, 3*chunkSize)); err != nil || res.Verdict != Clean {
		t.Fatalf("clean: %+v, %v", res, err)
	}
	res, err := scanBytes(t, c, antivirustest.EICAR())
	if err != nil || res.Verdict != Infected || res.Signature == "" {
		t.Fatalf("EICAR: %+v, %v", res, err)
	}
}

// lateCtx is a context whose deadline passed but whose Err is not set yet,
// as the connection deadline may notice it first.
type lateCtx struct{ context.Context }

func (lateCtx) Deadline() (time.Time, bool) { return time.Now().Add(-time.Second), true }

func TestExchangeErrorParentDeadline(t *testing.T) {
	parent := lateCtx{context.Background()}
	err := exchangeError(parent, parent, "read", os.ErrDeadlineExceeded)
	assertNotLost(t, err)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
}
