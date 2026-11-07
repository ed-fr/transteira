package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/textsafe"
)

// maxConfigBytes bounds the configuration file read by "config profiles".
const maxConfigBytes = client.MaxConfigFileBytes

// runConfig implements "config check" and "config profiles".
func runConfig(ctx context.Context, args []string, s streams) int {
	if len(args) > 0 {
		switch args[0] {
		case "check":
			return runConfigCheck(ctx, args[1:], s)
		case "profiles":
			return runConfigProfiles(ctx, args[1:], s)
		}
	}
	_, _ = fmt.Fprintf(s.err, "Usage: %s config (check|profiles) [options]\n", prog)
	if len(args) > 0 && args[0] != "-h" && args[0] != "--help" {
		return usageError(s, "unknown config command %q", args[0])
	}
	return exitUsage
}

// configCheckJSON is the --json output of config check.
type configCheckJSON struct {
	Profile    string `json:"profile,omitempty"`
	URL        string `json:"url"`
	ConfigFile string `json:"configFile,omitempty"`
	CAFile     string `json:"caFile,omitempty"`
	Sender     string `json:"sender,omitempty"`
	TokenSet   bool   `json:"tokenSet"`
}

// runConfigCheck resolves the configuration like the other commands, offline,
// and reports it without the token.
func runConfigCheck(_ context.Context, args []string, s streams) int {
	var conn connFlags
	fs := newFlagSet("config check", s.err)
	conn.add(fs, true)
	asJSON := fs.Bool("json", false, "print the result as JSON")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(s.err, "Usage: %s config check [options]\n", prog)
		fs.PrintDefaults()
	}
	if _, code, ok := parseFlags(fs, args, 0, 0, s.err); !ok {
		return code
	}
	cfg, err := client.Load(conn.loadOptions(false))
	if err != nil {
		return fail(s, err)
	}
	if _, err := newClient(cfg); err != nil {
		return fail(s, err)
	}
	if *asJSON {
		return printJSON(s, configCheckJSON{
			Profile: cfg.Profile, URL: cfg.URL, ConfigFile: cfg.ConfigFile,
			CAFile: cfg.CAFile, Sender: cfg.Sender, TokenSet: cfg.Token != "",
		})
	}
	show := func(label, v, none string) {
		if v == "" {
			v = none
		}
		_, _ = fmt.Fprintf(s.out, "%-12s %s\n", label+":", v)
	}
	show("profile", cfg.Profile, "(none)")
	show("url", cfg.URL, "")
	show("config file", cfg.ConfigFile, "(none)")
	show("ca file", cfg.CAFile, "(system authorities only)")
	show("sender", cfg.Sender, "(not set: --from is required to upload)")
	token := "set"
	if cfg.Token == "" {
		token = "not set (required to upload)"
	}
	show("token", token, "")
	_, _ = fmt.Fprintln(s.out, "Configuration is valid (no request was made).")
	return exitOK
}

// profilesFile is the part of the configuration file read by "config profiles".
type profilesFile struct {
	Default  string                    `json:"default"`
	Profiles map[string]map[string]any `json:"profiles"`
}

// profileEntry is one profile in the --json output of config profiles.
type profileEntry struct {
	Name    string `json:"name"`
	URL     string `json:"url,omitempty"`
	Default bool   `json:"default"`
}

// runConfigProfiles lists the profiles of the configuration file.
func runConfigProfiles(_ context.Context, args []string, s streams) int {
	var conn connFlags
	fs := newFlagSet("config profiles", s.err)
	fs.StringVar(&conn.config, "config", "", "configuration file (else "+client.EnvConfigFile+" or the user configuration directory)")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(s.err, "Usage: %s config profiles [options]\n", prog)
		fs.PrintDefaults()
	}
	if _, code, ok := parseFlags(fs, args, 0, 0, s.err); !ok {
		return code
	}
	path := conn.config
	explicit := path != ""
	if !explicit {
		path = os.Getenv(client.EnvConfigFile)
		explicit = path != ""
	}
	if !explicit {
		dir, err := os.UserConfigDir()
		if err != nil {
			return fail(s, fmt.Errorf("no configuration directory: %w", err))
		}
		path = filepath.Join(dir, "transteira", "config.json")
	}
	file, err := readProfiles(path)
	switch {
	case errors.Is(err, os.ErrNotExist) && !explicit:
		_, _ = fmt.Fprintf(s.out, "No configuration file (%s).\n", path)
		return exitOK
	case err != nil:
		return fail(s, err)
	}
	names := make([]string, 0, len(file.Profiles))
	for name := range file.Profiles {
		names = append(names, name)
	}
	slices.Sort(names)
	entries := make([]profileEntry, 0, len(names))
	for _, name := range names {
		u, _ := file.Profiles[name]["url"].(string)
		entries = append(entries, profileEntry{Name: name, URL: u, Default: name == file.Default})
	}
	if *asJSON {
		return printJSON(s, entries)
	}
	_, _ = fmt.Fprintf(s.out, "Configuration file: %s\n", path)
	for _, e := range entries {
		mark := " "
		if e.Default {
			mark = "*"
		}
		_, _ = fmt.Fprintf(s.out, "%s %s  %s\n", mark, textsafe.SanitizeMessage(e.Name), textsafe.SanitizeMessage(e.URL))
	}
	if len(entries) == 0 {
		_, _ = fmt.Fprintln(s.out, "(no profile)")
	} else {
		_, _ = fmt.Fprintln(s.out, "* = default profile")
	}
	return exitOK
}

// readProfiles reads the configuration file, refusing a file accessible by
// others outside Windows, like client.Load does.
func readProfiles(path string) (profilesFile, error) {
	var file profilesFile
	f, err := os.Open(path) //nolint:gosec // G304: the path is chosen by the user who runs the client
	if err != nil {
		return file, fmt.Errorf("configuration file: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return file, fmt.Errorf("configuration file %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return file, fmt.Errorf("configuration file %s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return file, fmt.Errorf("configuration file %s is accessible by other users (mode %04o): run chmod 600 %s",
			path, info.Mode().Perm(), path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return file, fmt.Errorf("configuration file %s: %w", path, err)
	}
	if len(data) > maxConfigBytes {
		return file, fmt.Errorf("configuration file %s is too large", path)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&file); err != nil {
		return file, fmt.Errorf("configuration file %s is not valid: %w", path, err)
	}
	return file, nil
}
