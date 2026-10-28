package app

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestRunSyslogExport checks the wiring of the syslog export: a security
// event of a running server reaches the syslog server configured by
// TT_SYSLOG_*, framed and formatted by package syslog.
func TestRunSyslogExport(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		lines := make(chan string, 4)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
			r := bufio.NewReader(c)
			for {
				line, err := r.ReadString(']')
				if err != nil {
					return
				}
				lines <- line
			}
		}()

		cfg := testConfig(t, e)
		prepare(t, cfg)
		if e.Driver == config.DriverPostgres {
			cfg.DBMigrateDSN = config.Secret{}
		}
		cfg.ClamAV.Address = fakeClamd(t)
		cfg.Syslog = config.SyslogConfig{
			Addr: ln.Addr().String(), Protocol: config.SyslogProtocolTCP,
			Streams: []string{config.SyslogStreamSecurity}, Facility: 16,
		}
		s := start(t, cfg)
		s.get(t, "/api/v1/version", "transfer.unknown.localhost")
		select {
		case line := <-lines:
			if !strings.Contains(line, "transteira") || !strings.Contains(line, "unknown_fqdn") {
				t.Errorf("syslog message %q", line)
			}
		case <-time.After(10 * time.Second):
			t.Error("no syslog message received")
		}
		if err := s.stop(t); err != nil {
			t.Fatalf("Run = %v", err)
		}
	})
}

type fakeCloser struct {
	err    error
	closed *[]string
	name   string
}

func (f fakeCloser) Close(context.Context) error {
	*f.closed = append(*f.closed, f.name)
	return f.err
}

// TestOutputsClose checks that outputs closes its members in order, all of
// them even when one fails, and joins their errors.
func TestOutputsClose(t *testing.T) {
	t.Parallel()
	var closed []string
	errA, errC := errors.New("a"), errors.New("c")
	o := outputs{
		fakeCloser{err: errA, closed: &closed, name: "bus"},
		fakeCloser{closed: &closed, name: "dispatcher"},
		fakeCloser{err: errC, closed: &closed, name: "syslog"},
	}
	err := o.Close(context.Background())
	if !errors.Is(err, errA) || !errors.Is(err, errC) {
		t.Errorf("Close = %v", err)
	}
	if strings.Join(closed, ",") != "bus,dispatcher,syslog" {
		t.Errorf("order %v", closed)
	}
	if err := (outputs{}).Close(context.Background()); err != nil {
		t.Errorf("empty Close = %v", err)
	}
}
