// Package antivirustest provides a fake clamd daemon for tests: it speaks
// the PING and INSTREAM commands ("z" variants), detects the EICAR test
// string, records what it receives and can misbehave on demand (size limit,
// connection closed mid-stream, hang, garbage reply, the heuristic
// signatures of a partial analysis, stop and restart on the same address).
// It is excluded from the coverage thresholds, like storetest.
//
// The server keeps every stream it receives in memory (see Server.Scans): it
// is meant for small test contents, not for large streams.
//
// It does not import package antivirus, so that the antivirus tests can use
// it too.
package antivirustest

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// Signatures reported by the server.
const (
	// EicarSignature is the signature the server reports for the EICAR
	// string.
	EicarSignature = "Eicar-Test-Signature"
	// LimitsExceededSignature is reported in ModeLimitsExceeded.
	LimitsExceededSignature = "Heuristics.Limits.Exceeded.MaxFiles"
	// EncryptedSignature is reported in ModeEncrypted.
	EncryptedSignature = "Heuristics.Encrypted.Zip"
)

// Replies sent by the server, NUL terminator excluded.
const (
	ReplyOK        = "stream: OK"
	ReplyFound     = "stream: " + EicarSignature + " FOUND"
	ReplySizeLimit = "INSTREAM size limit exceeded. ERROR"
	ReplyGarbage   = "stream: this is not a clamd verdict"
	// ReplyLimitsExceeded is what clamd answers with AlertExceedsMax when
	// it skipped content past its archive limits.
	ReplyLimitsExceeded = "stream: " + LimitsExceededSignature + " FOUND"
	// ReplyEncrypted is what clamd answers with AlertEncryptedArchive for
	// an encrypted archive.
	ReplyEncrypted = "stream: " + EncryptedSignature + " FOUND"
	ReplyPong      = "PONG"
	ReplyUnknown   = "UNKNOWN COMMAND"
)

// maxCommandLen bounds the length of a command line.
const maxCommandLen = 64

// EICAR returns the 68-byte EICAR antivirus test string. It is assembled
// from parts so that this source file is not flagged by scanners.
func EICAR() []byte {
	parts := []string{
		`X5O!P%@AP[4\PZX54(P^)7CC)7}$`,
		"EICAR-STANDARD-",
		"ANTIVIRUS-TEST-",
		"FILE!$H+H*",
	}
	var b bytes.Buffer
	for _, p := range parts {
		b.WriteString(p)
	}
	return b.Bytes()
}

// Mode selects how the server answers INSTREAM commands.
type Mode int

// Modes.
const (
	// ModeScan answers ReplyFound when the stream contains the EICAR
	// string, ReplyOK otherwise (and ReplySizeLimit beyond the size limit,
	// see SetSizeLimit).
	ModeScan Mode = iota
	// ModeCloseMidStream closes the connection after the first chunk (or
	// right after the command for an empty stream), without replying.
	ModeCloseMidStream
	// ModeHang reads the whole stream and never replies, until the server
	// stops.
	ModeHang
	// ModeGarbage reads the whole stream and replies ReplyGarbage.
	ModeGarbage
	// ModeLimitsExceeded reads the whole stream and replies
	// ReplyLimitsExceeded.
	ModeLimitsExceeded
	// ModeEncrypted reads the whole stream and replies ReplyEncrypted.
	ModeEncrypted
)

// Scan is one INSTREAM exchange as received by the server.
type Scan struct {
	// Data is the concatenated payload of the chunks received.
	Data []byte
	// Chunks holds the length of each data chunk, end marker excluded.
	Chunks []int
	// Complete reports whether the end-of-stream marker was received.
	Complete bool
}

// Server is a fake clamd listening on a local address. Its methods are safe
// for concurrent use.
type Server struct {
	network, address string

	mu        sync.Mutex
	ln        net.Listener
	conns     map[net.Conn]struct{}
	mode      Mode
	sizeLimit int64
	scans     []Scan
	pings     int
	wg        sync.WaitGroup
}

// New starts a fake clamd on a random TCP port of 127.0.0.1. It is closed
// when the test ends.
func New(t testing.TB) *Server {
	t.Helper()
	return start(t, "tcp", "127.0.0.1:0")
}

// NewUnix starts a fake clamd on the Unix socket path. The test is skipped
// when Unix sockets are not available. It is closed when the test ends.
func NewUnix(t testing.TB, path string) *Server {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("antivirustest: unix sockets unavailable: %v", err)
	}
	return serve(t, ln)
}

func start(t testing.TB, network, address string) *Server {
	t.Helper()
	ln, err := net.Listen(network, address)
	if err != nil {
		t.Fatalf("antivirustest: listen: %v", err)
	}
	return serve(t, ln)
}

func serve(t testing.TB, ln net.Listener) *Server {
	t.Helper()
	s := &Server{
		network: ln.Addr().Network(),
		address: ln.Addr().String(),
		conns:   make(map[net.Conn]struct{}),
	}
	s.listen(ln)
	t.Cleanup(s.Stop)
	return s
}

// Network returns "tcp" or "unix".
func (s *Server) Network() string { return s.network }

// Addr returns the listening address ("127.0.0.1:port" or the socket path).
func (s *Server) Addr() string { return s.address }

// SetMode changes how the following INSTREAM commands are answered.
func (s *Server) SetMode(m Mode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mode = m
}

// SetSizeLimit makes ModeScan answer ReplySizeLimit when a stream exceeds n
// bytes, like clamd's StreamMaxLength. The rest of the stream is drained
// before the connection is closed, so that the client always gets the
// reply. Zero or a negative value removes the limit.
func (s *Server) SetSizeLimit(n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sizeLimit = n
}

// Scans returns a copy of the INSTREAM exchanges received so far, in the
// order they ended.
func (s *Server) Scans() []Scan {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Scan, len(s.scans))
	for i, sc := range s.scans {
		out[i] = Scan{
			Data:     bytes.Clone(sc.Data),
			Chunks:   append([]int(nil), sc.Chunks...),
			Complete: sc.Complete,
		}
	}
	return out
}

// Pings returns the number of PING commands received.
func (s *Server) Pings() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pings
}

// Stop closes the listener and every open connection, and waits for the
// handlers to return, like a clamd going down. Stopping a stopped server
// does nothing.
func (s *Server) Stop() {
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

// Restart listens again on the same address after Stop, like a clamd
// coming back. It retries for a few seconds while the address is still
// held by the system. Restarting a running server does nothing.
func (s *Server) Restart(t testing.TB) {
	t.Helper()
	s.mu.Lock()
	running := s.ln != nil
	s.mu.Unlock()
	if running {
		return
	}
	var err error
	for deadline := time.Now().Add(5 * time.Second); ; {
		var ln net.Listener
		if ln, err = net.Listen(s.network, s.address); err == nil {
			s.listen(ln)
			return
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("antivirustest: restart on %s: %v", s.address, err)
}

// listen starts accepting connections on ln.
func (s *Server) listen(ln net.Listener) {
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			if !s.track(conn) {
				_ = conn.Close()
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer s.untrack(conn)
				s.handle(conn)
			}()
		}
	}()
}

// track registers conn, unless the listener it came from was stopped.
func (s *Server) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *Server) untrack(conn net.Conn) {
	_ = conn.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, conn)
}

// handle serves one command.
func (s *Server) handle(conn net.Conn) {
	br := bufio.NewReader(conn)
	cmd, err := readCommand(br)
	if err != nil {
		return
	}
	switch cmd {
	case "zPING":
		s.mu.Lock()
		s.pings++
		s.mu.Unlock()
		reply(conn, ReplyPong)
	case "zINSTREAM":
		s.instream(conn, br)
	default:
		reply(conn, ReplyUnknown)
	}
}

// readCommand reads a NUL-terminated command.
func readCommand(br *bufio.Reader) (string, error) {
	var b []byte
	for len(b) <= maxCommandLen {
		c, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		if c == 0 {
			return string(b), nil
		}
		b = append(b, c)
	}
	return "", errors.New("command too long")
}

// instream serves an INSTREAM command.
func (s *Server) instream(conn net.Conn, br *bufio.Reader) {
	s.mu.Lock()
	mode, limit := s.mode, s.sizeLimit
	s.mu.Unlock()

	var sc Scan
	defer func() {
		s.mu.Lock()
		s.scans = append(s.scans, sc)
		s.mu.Unlock()
	}()
	overLimit := false
	for {
		if mode == ModeCloseMidStream && (len(sc.Chunks) > 0 || sc.Complete) {
			return
		}
		var hdr [4]byte
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 {
			sc.Complete = true
			if mode == ModeCloseMidStream {
				return
			}
			break
		}
		chunk := make([]byte, n)
		if _, err := io.ReadFull(br, chunk); err != nil {
			return
		}
		sc.Chunks = append(sc.Chunks, int(n))
		sc.Data = append(sc.Data, chunk...)
		if mode == ModeScan && limit > 0 && !overLimit && int64(len(sc.Data)) > limit {
			overLimit = true
			reply(conn, ReplySizeLimit)
		}
	}
	switch {
	case overLimit:
		// Already answered.
	case mode == ModeHang:
		_, _ = io.Copy(io.Discard, br)
	case mode == ModeGarbage:
		reply(conn, ReplyGarbage)
	case mode == ModeLimitsExceeded:
		reply(conn, ReplyLimitsExceeded)
	case mode == ModeEncrypted:
		reply(conn, ReplyEncrypted)
	case bytes.Contains(sc.Data, EICAR()):
		reply(conn, ReplyFound)
	default:
		reply(conn, ReplyOK)
	}
}

// reply writes a NUL-terminated reply.
func reply(conn net.Conn, text string) {
	_, _ = conn.Write(append([]byte(text), 0))
}
