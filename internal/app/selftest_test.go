package app

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/antivirus"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/avselftest"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// cleanClamd starts a fake clamd that answers PONG to every PING and
// "stream: OK" to every INSTREAM, EICAR included, and returns its address
// and a function returning the sizes of the streams it analyzed.
func cleanClamd(t *testing.T) (string, func() []int) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var sizes []int
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				r := bufio.NewReader(c)
				cmd, err := r.ReadBytes(0)
				if err != nil {
					return
				}
				if string(cmd) != "zINSTREAM\x00" {
					_, _ = c.Write([]byte("PONG\x00"))
					return
				}
				total := 0
				for {
					var n uint32
					if binary.Read(r, binary.BigEndian, &n) != nil {
						return
					}
					if n == 0 {
						break
					}
					if _, err := io.CopyN(io.Discard, r, int64(n)); err != nil {
						return
					}
					total += int(n)
				}
				mu.Lock()
				sizes = append(sizes, total)
				mu.Unlock()
				_, _ = c.Write([]byte("stream: OK\x00"))
			}()
		}
	}()
	return ln.Addr().String(), func() []int {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(sizes)
	}
}

// selfTestEvents returns the antivirus.self_test events of the database of
// cfg.
func selfTestEvents(t *testing.T, cfg *config.Config) []store.AuditEvent {
	t.Helper()
	ctx := context.Background()
	c := *cfg
	db, err := store.Open(ctx, &c)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	page, err := db.AuditEvents().List(ctx, store.AuditFilter{Action: string(audit.ActionAntivirusSelfTest)})
	if err != nil {
		t.Fatal(err)
	}
	return page.Items
}

// TestRunAntivirusSelfTestPasses starts the instance with a fake clamd
// detecting EICAR: the start-up self-test passes before the worker starts,
// /healthz reports the antivirus ok, and the test is audited once (actor
// system) and logged without the engine address.
func TestRunAntivirusSelfTestPasses(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		cfg := testConfig(t, e)
		prepare(t, cfg)
		if e.Driver == config.DriverPostgres {
			cfg.DBMigrateDSN = config.Secret{}
		}
		cfg.ClamAV.Address = fakeClamd(t)
		s := start(t, cfg)
		if code, body := s.get(t, "/healthz", "x"); code != http.StatusOK || !strings.Contains(body, `"antivirus":"ok"`) {
			t.Fatalf("healthz = %d %s", code, body)
		}
		if err := s.stop(t); err != nil {
			t.Fatalf("Run = %v", err)
		}
		evs := selfTestEvents(t, cfg)
		if len(evs) != 1 || evs[0].ActorKind != store.ActorSystem || evs[0].Actor != audit.ActorAntivirus || evs[0].TenantID != "" {
			t.Fatalf("self-test events %+v", evs)
		}
		var details map[string]string
		if err := json.Unmarshal(evs[0].Details, &details); err != nil ||
			details["engine"] != "clamd" || details["outcome"] != "detected" || details["trigger"] != "startup" {
			t.Fatalf("details %s, %v", evs[0].Details, err)
		}
		if logs := s.logs.String(); !strings.Contains(logs, "antivirus self-test passed") || strings.Contains(logs, cfg.ClamAV.Address) {
			t.Errorf("logs: %s", logs)
		}
	})
}

// TestRunAntivirusSelfTestFails starts the instance with an engine that
// reports everything clean, EICAR included: the gate stays closed, so the
// file waiting at start-up is never sent to the engine and stays waiting,
// /healthz reports the antivirus unavailable, and the failure is logged at
// ERROR level.
func TestRunAntivirusSelfTestFails(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		cfg := testConfig(t, e)
		prepare(t, cfg)
		tid, trfID := waitingTransfer(t, cfg)
		if e.Driver == config.DriverPostgres {
			cfg.DBMigrateDSN = config.Secret{}
		}
		addr, sizes := cleanClamd(t)
		cfg.ClamAV.Address = addr
		s := start(t, cfg)
		if code, body := s.get(t, "/healthz", "x"); code != http.StatusServiceUnavailable || !strings.Contains(body, `"antivirus":"unavailable"`) {
			t.Fatalf("healthz = %d %s", code, body)
		}
		time.Sleep(200 * time.Millisecond) // leave the worker time to (not) scan
		if err := s.stop(t); err != nil {
			t.Fatalf("Run = %v", err)
		}
		// Only the 68-byte EICAR string reached the engine.
		got := sizes()
		if len(got) == 0 || slices.ContainsFunc(got, func(n int) bool { return n != len(antivirus.EICAR()) }) {
			t.Fatalf("streams analyzed %v", got)
		}
		ctx := context.Background()
		c := *cfg
		db, err := store.Open(ctx, &c)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		d, err := db.Transfers().Get(ctx, tid, trfID)
		if err != nil {
			t.Fatal(err)
		}
		if d.Status != store.TransferScanning || (d.Files[0].ScanStatus != store.ScanPending && d.Files[0].ScanStatus != store.ScanScanning) {
			t.Fatalf("transfer %s, file %s", d.Status, d.Files[0].ScanStatus)
		}
		evs := selfTestEvents(t, cfg)
		var details map[string]string
		if len(evs) != 1 || json.Unmarshal(evs[0].Details, &details) != nil || details["outcome"] != "not_detected" {
			t.Fatalf("self-test events %+v", evs)
		}
		if logs := s.logs.String(); !strings.Contains(logs, `"level":"ERROR","msg":"antivirus self-test failed`) {
			t.Errorf("logs: %s", logs)
		}
	})
}

func TestNewAntivirusEngine(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{AntivirusEngine: config.EngineNone}
	if eng, _, err := newAntivirusEngine(cfg); eng != nil || err != nil {
		t.Fatalf("none: %v, %v", eng, err)
	}
	cfg = &config.Config{
		AntivirusEngine: config.EngineClamd, ClamAVTimeout: time.Minute,
		ClamAV: config.ClamAVAddr{Network: "tcp", Address: "clamav:3310"},
	}
	if eng, d, err := newAntivirusEngine(cfg); err != nil || d != time.Minute {
		t.Fatalf("clamd: %v, %v", d, err)
	} else if _, ok := eng.(*antivirus.Client); !ok {
		t.Fatalf("clamd engine %T", eng)
	}
	cfg = &config.Config{AntivirusEngine: config.EngineICAP, ICAP: config.ICAPConfig{
		URL: "icap://icap:1344/avscan", MaxScanBytes: 1 << 20, Timeout: 2 * time.Minute,
		InfectionHeaders: []string{"X-Infection-Found"},
	}}
	if eng, d, err := newAntivirusEngine(cfg); err != nil || d != 2*time.Minute {
		t.Fatalf("icap: %v, %v", d, err)
	} else if _, ok := eng.(*antivirus.ICAPClient); !ok {
		t.Fatalf("icap engine %T", eng)
	}
	cfg.ICAP.URL = "icap://icap:1344/"
	if _, _, err := newAntivirusEngine(cfg); err == nil || !strings.Contains(err.Error(), config.EnvICAPURL) {
		t.Fatalf("icap without service: %v", err)
	}
	h := config.AVHTTPConfig{
		URL: "https://scanner.example.com/scan", Method: "POST", Body: config.AVHTTPBodyMultipart, MultipartField: "file",
		AuthHeader: config.NewSecret("Authorization: Bearer s3cr3t"), CleanRule: "status=200 && json:/infected=false",
		InfectedRule: "status=200 && json:/infected=true", MaxScanBytes: 1 << 20, Timeout: 3 * time.Minute,
	}
	cfg = &config.Config{AntivirusEngine: config.EngineHTTP, AVHTTP: h}
	if eng, d, err := newAntivirusEngine(cfg); err != nil || d != 3*time.Minute {
		t.Fatalf("http: %v, %v", d, err)
	} else if _, ok := eng.(*antivirus.HTTPClient); !ok {
		t.Fatalf("http engine %T", eng)
	}
	for _, c := range []struct {
		edit func(*config.AVHTTPConfig)
		want string
	}{
		{func(h *config.AVHTTPConfig) { h.CleanRule = "bogus" }, config.EnvAVHTTPCleanRule},
		{func(h *config.AVHTTPConfig) { h.InfectedRule = "status=" }, config.EnvAVHTTPInfectedRule},
		{func(h *config.AVHTTPConfig) { h.URL = "ftp://scanner/scan" }, config.EnvAVHTTPURL},
	} {
		bad := h
		c.edit(&bad)
		_, _, err := newAntivirusEngine(&config.Config{AntivirusEngine: config.EngineHTTP, AVHTTP: bad})
		if err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "s3cr3t") {
			t.Errorf("%s: %v", c.want, err)
		}
	}
}

func TestAntivirusScannerWiring(t *testing.T) {
	t.Parallel()
	none := avselftest.New(nil, avselftest.Options{})
	if antivirusScanner(none) != nil || selfTestLast(none) != nil || selfTestPassed(none) != nil {
		t.Fatal("none has a scanner or sources")
	}
	if err := startSelfTests(context.Background(), none); err != nil {
		t.Fatal(err)
	}
	eng := antivirus.NewClient("tcp", "127.0.0.1:1")
	svc := avselftest.New(eng, avselftest.Options{})
	if antivirusScanner(svc) != svc.Gate() {
		t.Fatal("scanner")
	}
	if selfTestLast(svc) == nil || selfTestPassed(svc) == nil {
		t.Fatal("sources")
	}
	// A closed service refuses to start.
	if err := svc.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := startSelfTests(context.Background(), svc); !errors.Is(err, avselftest.ErrClosed) {
		t.Fatalf("closed: %v", err)
	}
}
