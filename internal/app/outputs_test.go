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
	"github.com/ed-fr/transteira/internal/events"
	"github.com/ed-fr/transteira/internal/metrics"
	"github.com/ed-fr/transteira/internal/securityevents"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/webhook"
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

// fakeBusDrops reports a fixed number of drops per subscriber.
type fakeBusDrops map[string]uint64

func (f fakeBusDrops) Dropped(subscriber string) uint64 { return f[subscriber] }

// fakeDropped reports a fixed number of drops.
type fakeDropped uint64

func (f fakeDropped) Dropped() uint64 { return uint64(f) }

// TestBusDrops checks that the supervision counts the drops of the
// security events recorder itself (refused batch, pending overflow)
// through Recorder.Dropped, without adding its bus queue drops twice,
// and the bus drops of every other subscriber.
func TestBusDrops(t *testing.T) {
	t.Parallel()
	bus := fakeBusDrops{securityevents.SubscriberName: 3, webhook.SubscriberName: 2}
	d := busDrops{bus: bus, securityEvents: fakeDropped(7)} // 7 = 3 bus + 4 own
	if got := d.Dropped(securityevents.SubscriberName); got != 7 {
		t.Errorf("security events drops %d, want 7", got)
	}
	if got := d.Dropped(webhook.SubscriberName); got != 2 {
		t.Errorf("webhook drops %d, want 2", got)
	}

	src := supervisionSources(busOutputs{}, metrics.Sources{Bus: bus})
	if _, wrapped := src.Bus.(busDrops); wrapped {
		t.Error("bus wrapped without a security events recorder")
	}
	rec, err := securityevents.New(securityevents.Options{Store: failingSecurityStore{}})
	if err != nil {
		t.Fatal(err)
	}
	src = supervisionSources(busOutputs{securityEvents: rec}, metrics.Sources{Bus: bus})
	// The recorder is not registered on a bus: its drops are its own.
	rec.Add(context.Background(), events.LogRecord{
		Stream: events.StreamSecurity, Action: "unknown_fqdn", Time: time.Now(),
	})
	_ = rec.Flush(context.Background()) // refused as malformed: dropped
	if got := src.Bus.Dropped(securityevents.SubscriberName); got != 1 {
		t.Errorf("security events drops %d, want the recorder drop 1", got)
	}
	if got := src.Bus.Dropped(webhook.SubscriberName); got != 2 {
		t.Errorf("webhook drops %d, want 2", got)
	}
	if src = supervisionSources(busOutputs{securityEvents: rec}, metrics.Sources{}); src.Bus != nil {
		t.Errorf("bus %v without a bus", src.Bus)
	}
}

// failingSecurityStore refuses every batch as malformed.
type failingSecurityStore struct{}

func (failingSecurityStore) Save(context.Context, []store.SecurityEvent) ([]store.SecurityEvent, error) {
	return nil, store.ErrInvalid
}
