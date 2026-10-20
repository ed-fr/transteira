package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ed-fr/transteira/internal/app"
	"github.com/ed-fr/transteira/internal/config"
)

// healthcheckTimeout bounds the healthcheck request.
const healthcheckTimeout = 3 * time.Second

// runApp starts the server; replaced in tests.
var runApp = app.Run

// runServe loads the configuration from the environment and runs the
// server until SIGINT or SIGTERM.
func runServe(args []string, _, stderr io.Writer) int {
	fs := newFlagSet("serve", stderr)
	if code, ok := parseFlags(fs, args, stderr); !ok {
		return code
	}
	cfg, err := config.FromEnvironment()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "serve: %v\n", err)
		return exitError
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runApp(ctx, cfg); err != nil {
		_, _ = fmt.Fprintf(stderr, "serve: %v\n", err)
		return exitError
	}
	return exitOK
}

// runHealthcheck probes /healthz of the local server and exits 0 when it
// answers 200, 1 otherwise. It needs no shell nor curl, for the Docker
// HEALTHCHECK of a scratch image, and reads only TT_LISTEN_ADDR.
func runHealthcheck(args []string, _, stderr io.Writer) int {
	fs := newFlagSet("healthcheck", stderr)
	target := fs.String("url", "", "health check URL (default http://127.0.0.1:<port of TT_LISTEN_ADDR>/healthz)")
	if code, ok := parseFlags(fs, args, stderr); !ok {
		return code
	}
	u := *target
	if u == "" {
		var err error
		if u, err = defaultHealthURL(os.Getenv(config.EnvListenAddr)); err != nil {
			_, _ = fmt.Fprintf(stderr, "healthcheck: %v\n", err)
			return exitUsage
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), healthcheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil) //nolint:gosec // G704: the URL comes from the operator (flag or TT_LISTEN_ADDR), not from a request
	if err != nil || (req.URL.Scheme != "http" && req.URL.Scheme != "https") || req.URL.Host == "" {
		_, _ = fmt.Fprintf(stderr, "healthcheck: invalid URL %q\n", u)
		return exitUsage
	}
	// No proxy: the probe always targets the local server.
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Do(req) //nolint:gosec // G704: operator-supplied local health URL
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "healthcheck: %v\n", err)
		return exitError
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = fmt.Fprintf(stderr, "healthcheck: %s answered %s\n", u, resp.Status)
		return exitError
	}
	return exitOK
}

// defaultHealthURL builds the /healthz URL of the server listening on
// listenAddr (TT_LISTEN_ADDR; empty means config.DefaultListenAddr). A
// wildcard or empty host is probed on 127.0.0.1.
func defaultHealthURL(listenAddr string) (string, error) {
	listenAddr = strings.TrimSpace(listenAddr)
	if listenAddr == "" {
		listenAddr = config.DefaultListenAddr
	}
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil || port == "" {
		return "", fmt.Errorf("invalid %s %q", config.EnvListenAddr, listenAddr)
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz", nil
}
