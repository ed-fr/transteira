// Package antivirus talks to a ClamAV clamd daemon over TCP or a Unix socket.
//
// Only the PING command is implemented for now; it backs the health check.
// The Client keeps the dial parameters (network, address, dialer, timeout)
// rather than a live connection, so that the INSTREAM scanning command can be
// added later as another method opening its own short-lived connection, with
// its own (longer) deadline and the same error conventions.
//
// Errors returned by this package may contain the clamd address (dial errors
// from the net package do). Callers exposing results over HTTP must map them
// to a generic status and never forward the error text.
package antivirus

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// DefaultTimeout bounds a whole PING exchange (dial, write and read) when no
// WithTimeout option is given.
const DefaultTimeout = 2 * time.Second

// maxReplyLen bounds the size of a clamd reply read by Ping, so that a
// misbehaving peer cannot make the client buffer an unbounded amount of data.
const maxReplyLen = 64

// Commands use the "z" prefix: the command and the reply are terminated by a
// NUL byte instead of a newline.
var (
	pingCommand = []byte("zPING\x00")
	pongReply   = []byte("PONG")
)

// ErrUnexpectedReply is returned when clamd answers something unexpected.
var ErrUnexpectedReply = errors.New("antivirus: unexpected clamd reply")

// DialFunc opens a connection to clamd. It has the signature of
// (*net.Dialer).DialContext.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Client is a clamd client. It is safe for concurrent use: every command opens
// its own connection.
type Client struct {
	network string
	address string
	timeout time.Duration
	dial    DialFunc
}

// Option customizes a Client.
type Option func(*Client)

// WithTimeout sets the maximum duration of a PING exchange. Non-positive
// values are ignored.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithDialer replaces the function used to connect to clamd. A nil dialer is
// ignored.
func WithDialer(dial DialFunc) Option {
	return func(c *Client) {
		if dial != nil {
			c.dial = dial
		}
	}
}

// NewClient returns a client for the clamd daemon listening on address.
// network is "tcp" (address "host:port") or "unix" (address is the socket
// path). No connection is opened until a command is sent.
func NewClient(network, address string, opts ...Option) *Client {
	c := &Client{
		network: network,
		address: address,
		timeout: DefaultTimeout,
		dial:    (&net.Dialer{}).DialContext,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Ping checks that clamd is reachable and answers PONG to a PING command.
// The exchange is bounded by the client timeout and by ctx.
func (c *Client) Ping(ctx context.Context) (err error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	conn, err := c.dial(ctx, c.network, c.address)
	if err != nil {
		return fmt.Errorf("antivirus: ping: dial: %w", err)
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("antivirus: ping: close: %w", cerr)
		}
	}()
	// The deadline enforces the timeout; AfterFunc unblocks I/O on cancel.
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("antivirus: ping: set deadline: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	if _, err := conn.Write(pingCommand); err != nil {
		return fmt.Errorf("antivirus: ping: write: %w", err)
	}
	reply, err := readReply(conn)
	if err != nil {
		return fmt.Errorf("antivirus: ping: read: %w", err)
	}
	if !bytes.Equal(reply, pongReply) {
		return fmt.Errorf("%w to PING", ErrUnexpectedReply)
	}
	return nil
}

// readReply reads one NUL-terminated clamd reply, without the terminator.
func readReply(r io.Reader) ([]byte, error) {
	br := bufio.NewReaderSize(io.LimitReader(r, maxReplyLen), maxReplyLen)
	reply, err := br.ReadBytes(0)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: missing terminator", ErrUnexpectedReply)
		}
		return nil, err
	}
	return reply[:len(reply)-1], nil
}
