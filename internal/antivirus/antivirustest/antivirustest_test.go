package antivirustest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func exchange(t *testing.T, s *Server, payload []byte) string {
	t.Helper()
	conn, err := net.DialTimeout(s.Network(), s.Addr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	// Half-close so that the server sees the end of truncated streams.
	_ = conn.(interface{ CloseWrite() error }).CloseWrite()
	reply, _ := io.ReadAll(conn)
	return string(reply)
}

func instream(chunks ...[]byte) []byte {
	b := []byte("zINSTREAM\x00")
	for _, c := range chunks {
		n := len(c)
		b = append(b, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
		b = append(b, c...)
	}
	return append(b, 0, 0, 0, 0)
}

func TestEICAR(t *testing.T) {
	sum := sha256.Sum256(EICAR())
	// Published SHA-256 of the 68-byte EICAR test string.
	const want = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
	if len(EICAR()) != 68 || hex.EncodeToString(sum[:]) != want {
		t.Fatalf("EICAR() = %q", EICAR())
	}
}

func TestServer(t *testing.T) {
	s := New(t)
	if got := exchange(t, s, []byte("zPING\x00")); got != ReplyPong+"\x00" || s.Pings() != 1 {
		t.Fatalf("PING = %q, pings %d", got, s.Pings())
	}
	if got := exchange(t, s, []byte("zVERSION\x00")); got != ReplyUnknown+"\x00" {
		t.Fatalf("VERSION = %q", got)
	}
	if got := exchange(t, s, []byte(strings.Repeat("z", 100))); got != "" {
		t.Fatalf("long command = %q", got)
	}
	if got := exchange(t, s, instream([]byte("abc"), []byte("de"))); got != ReplyOK+"\x00" {
		t.Fatalf("clean = %q", got)
	}
	if got := exchange(t, s, instream(EICAR()[:30], EICAR()[30:])); got != ReplyFound+"\x00" {
		t.Fatalf("EICAR = %q", got)
	}
	s.SetSizeLimit(4)
	if got := exchange(t, s, instream([]byte("abc"), []byte("de"), []byte("fg"))); got != ReplySizeLimit+"\x00" {
		t.Fatalf("size limit = %q", got)
	}
	s.SetSizeLimit(0)
	s.SetMode(ModeGarbage)
	if got := exchange(t, s, instream([]byte("abc"))); got != ReplyGarbage+"\x00" {
		t.Fatalf("garbage = %q", got)
	}
	s.SetMode(ModeCloseMidStream)
	if got := exchange(t, s, instream()); got != "" {
		t.Fatalf("close empty = %q", got)
	}
	if got := exchange(t, s, instream([]byte("abc"))); got != "" {
		t.Fatalf("close = %q", got)
	}
	// Truncated streams are recorded as incomplete.
	s.SetMode(ModeScan)
	_ = exchange(t, s, []byte("zINSTREAM\x00\x00\x00"))
	_ = exchange(t, s, []byte("zINSTREAM\x00\x00\x00\x00\x05ab"))

	scans := s.Scans()
	if len(scans) != 8 {
		t.Fatalf("%d scans", len(scans))
	}
	if sc := scans[0]; !sc.Complete || string(sc.Data) != "abcde" || len(sc.Chunks) != 2 || sc.Chunks[1] != 2 {
		t.Fatalf("scan 0 = %+v", sc)
	}
	if sc := scans[4]; !sc.Complete || len(sc.Chunks) != 0 {
		t.Fatalf("scan 4 = %+v", sc)
	}
	if scans[6].Complete || scans[7].Complete || !bytes.Equal(scans[6].Data, nil) {
		t.Fatalf("truncated scans = %+v", scans[6:])
	}
}

func TestServerHangStopRestart(t *testing.T) {
	s := New(t)
	s.Restart(t) // running: no-op
	s.SetMode(ModeHang)

	conn, err := net.Dial("tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(instream([]byte("abc"))); err != nil {
		t.Fatal(err)
	}
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(conn)
		done <- b
	}()
	select {
	case b := <-done:
		t.Fatalf("hang mode replied %q", b)
	case <-time.After(100 * time.Millisecond):
	}
	s.Stop()
	if b := <-done; len(b) != 0 {
		t.Fatalf("reply after stop = %q", b)
	}
	s.Stop() // stopped: no-op
	if _, err := net.DialTimeout("tcp", s.Addr(), time.Second); err == nil {
		t.Fatal("dial succeeded on a stopped server")
	}

	s.Restart(t)
	s.SetMode(ModeScan)
	if got := exchange(t, s, []byte("zPING\x00")); got != ReplyPong+"\x00" {
		t.Fatalf("PING after restart = %q", got)
	}
}

func TestHeuristicModes(t *testing.T) {
	s := New(t)
	s.SetMode(ModeLimitsExceeded)
	if got := exchange(t, s, instream([]byte("abc"))); got != ReplyLimitsExceeded+"\x00" {
		t.Fatalf("limits exceeded = %q", got)
	}
	s.SetMode(ModeEncrypted)
	if got := exchange(t, s, instream([]byte("abc"))); got != ReplyEncrypted+"\x00" {
		t.Fatalf("encrypted = %q", got)
	}
}
