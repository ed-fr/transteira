package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ed-fr/transteira/internal/cli/client"
)

// maxSecretFileBytes bounds a password, key or message file.
const maxSecretFileBytes = 64 << 10

// printJSON writes v as one indented JSON document on stdout.
func printJSON(s streams, v any) int {
	enc := json.NewEncoder(s.out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fail(s, err)
	}
	return exitOK
}

// stringList is a repeatable flag; with split set, each value may also be a
// comma separated list.
type stringList struct {
	split  bool
	values []string
}

// String implements flag.Value.
func (l *stringList) String() string { return strings.Join(l.values, ",") }

// Set implements flag.Value.
func (l *stringList) Set(v string) error {
	if !l.split {
		l.values = append(l.values, v)
		return nil
	}
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			l.values = append(l.values, p)
		}
	}
	return nil
}

// connFlags are the flags shared by the commands that reach the server.
type connFlags struct {
	url, tokenFile, sender, profile, config, caFile string
	verbose                                         bool
}

// add registers the connection flags on fs; withSender adds --sender.
func (c *connFlags) add(fs *flag.FlagSet, withSender bool) {
	fs.StringVar(&c.url, "url", "", "tenant URL https://host[:port] (else "+client.EnvURL+" or the profile)")
	fs.StringVar(&c.tokenFile, "token-file", "", "file holding the API token (else "+client.EnvTokenFile+", "+client.EnvToken+" or the profile)")
	if withSender {
		fs.StringVar(&c.sender, "sender", "", "default sender address (else "+client.EnvSender+" or the profile)")
	}
	fs.StringVar(&c.profile, "profile", "", "profile of the configuration file (else "+client.EnvProfile+" or the default one)")
	fs.StringVar(&c.config, "config", "", "configuration file (else "+client.EnvConfigFile+" or the user configuration directory)")
	fs.StringVar(&c.caFile, "ca-file", "", "PEM file of extra certificate authorities (else "+client.EnvCAFile+" or the profile)")
	fs.BoolVar(&c.verbose, "verbose", false, "log every request (without secrets) on the error output")
}

// loadOptions converts the flags into client.LoadOptions.
func (c *connFlags) loadOptions(requireToken bool) client.LoadOptions {
	return client.LoadOptions{
		URL: c.url, TokenFile: c.tokenFile, Sender: c.sender, Profile: c.profile,
		ConfigFile: c.config, CAFile: c.caFile, RequireToken: requireToken,
	}
}

// clientOptions returns the options of client.New.
func (c *connFlags) clientOptions(s streams) []client.Option {
	if c.verbose {
		return []client.Option{client.WithLogger(s.err)}
	}
	return nil
}

// progressPrinter prints throttled progress lines on w.
type progressPrinter struct {
	w        io.Writer
	interval time.Duration
	mu       sync.Mutex
	last     time.Time
	label    string
}

// newProgressPrinter returns a printer writing at most one line per interval
// (and one at each change of label and at completion).
func newProgressPrinter(w io.Writer, interval time.Duration) *progressPrinter {
	return &progressPrinter{w: w, interval: interval}
}

// print writes "label: done/total" when due.
func (p *progressPrinter) print(label string, done, total int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	final := total > 0 && done >= total
	if label == p.label && !final && now.Sub(p.last) < p.interval {
		return
	}
	p.label, p.last = label, now
	if total > 0 {
		_, _ = fmt.Fprintf(p.w, "%s: %s / %s (%d%%)\n", label, humanSize(done), humanSize(total), done*100/total)
	} else {
		_, _ = fmt.Fprintf(p.w, "%s: %s\n", label, humanSize(done))
	}
}

// humanSize formats a byte count with binary units.
func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// parseSize parses a size in bytes, optionally suffixed KiB, MiB or GiB.
func parseSize(v string) (int64, error) {
	s := strings.ToLower(strings.TrimSpace(v))
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		mult   int64
	}{{"kib", 1 << 10}, {"mib", 1 << 20}, {"gib", 1 << 30}} {
		if t, ok := strings.CutSuffix(s, u.suffix); ok {
			s, mult = strings.TrimSpace(t), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n > (1<<62)/mult {
		return 0, fmt.Errorf("invalid size %q: use a number of bytes, or KiB, MiB, GiB (for example 100MiB)", v)
	}
	return n * mult, nil
}

// readSecretFile reads a small secret file (password, key): it must be a
// regular file and, outside Windows, not accessible by the group or others.
// One trailing line ending is removed.
func readSecretFile(path, what string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path is chosen by the user who runs the client
	if err != nil {
		return "", fmt.Errorf("%s file: %w", what, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("%s file %s: %w", what, path, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s file %s is not a regular file", what, path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s file %s is accessible by other users (mode %04o): run chmod 600 %s",
			what, path, info.Mode().Perm(), path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSecretFileBytes+1))
	if err != nil {
		return "", fmt.Errorf("%s file %s: %w", what, path, err)
	}
	if len(data) > maxSecretFileBytes {
		return "", fmt.Errorf("%s file %s is larger than %d bytes", what, path, maxSecretFileBytes)
	}
	data = bytes.TrimSuffix(data, []byte("\n"))
	data = bytes.TrimSuffix(data, []byte("\r"))
	return string(data), nil
}

// errNeedTerminal is wrapped by promptSecret when no terminal is available.
var errNeedTerminal = errors.New("a terminal is needed to type it")

// promptSecret asks for a value on the terminal of s without echo. flagHint
// names the option to use when the input is not a terminal.
func promptSecret(s streams, label, flagHint string) (string, error) {
	if !isTerminal(s.in) {
		return "", fmt.Errorf("%s required: %w; use %s", label, errNeedTerminal, flagHint)
	}
	fd, _ := fdOf(s.in)
	_, _ = fmt.Fprintf(s.err, "%s: ", label)
	b, err := readPassword(fd)
	_, _ = fmt.Fprintln(s.err)
	if err != nil {
		return "", fmt.Errorf("reading the %s: %w", label, err)
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}
