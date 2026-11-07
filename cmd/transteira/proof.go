package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/app"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/config"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/proof"
	"github.com/ed-fr/transteira/internal/proofverify"
)

// stdin is the input of the confirmation prompt; tests replace it.
var stdin io.Reader = os.Stdin

// stdinIsTerminal reports whether the confirmation can be asked; tests
// replace it.
var stdinIsTerminal = func() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// runProof dispatches "proof verify", "proof keys" and "proof retire-key".
func runProof(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "verify":
			return runProofVerify(args[1:], stdout, stderr)
		case "keys":
			return runProofKeys(args[1:], stdout, stderr)
		case "retire-key":
			return runProofRetireKey(args[1:], stdout, stderr)
		}
	}
	_, _ = fmt.Fprintln(stderr, "Usage: transteira proof <verify|keys|retire-key> [flags]\n\n"+
		"  verify      [--keys FILE | --url https://FQDN] [--json] <proof.pdf>  Verify a proof offline\n"+
		"  keys                                                              List the signing keys (database)\n"+
		"  retire-key  [--yes]                                               Retire the active signing key")
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		return exitOK
	}
	return exitUsage
}

// runProofVerify verifies a proof PDF against the public keys of an
// instance; it needs neither the database nor the master key.
func runProofVerify(args []string, stdout, stderr io.Writer) int {
	return runProofVerifyWith(context.Background(), proofverify.NewKeysClient(), args, stdout, stderr)
}

// runProofVerifyWith is [runProofVerify] with the context and the HTTP
// client that downloads the public keys; tests pass a client trusting their
// server.
func runProofVerifyWith(ctx context.Context, client *http.Client, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("proof verify", stderr)
	keysFile := fs.String("keys", "", "file holding the saved answer of GET /api/v1/proof-keys")
	keysURL := fs.String("url", "", "https URL of the instance (https://FQDN), or of its proof keys")
	asJSON := fs.Bool("json", false, "print the verified statement as canonical JSON")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage: transteira proof verify [--keys FILE | --url https://FQDN] [--json] <proof.pdf>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if (*keysFile == "") == (*keysURL == "") || fs.NArg() != 1 {
		fs.Usage()
		_, _ = fmt.Fprintln(stderr, "proof verify: give exactly one of --keys and --url, and one PDF file")
		return exitUsage
	}
	st, data, err := proofverify.Verify(ctx, proofverify.Options{File: fs.Arg(0), URL: *keysURL, KeysFile: *keysFile, Client: client})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "proof verify: %s\n", proofverify.Failure(err))
		return exitError
	}
	if *asJSON {
		_, err = stdout.Write(append(data, '\n'))
	} else {
		err = proofverify.PrintStatement(stdout, st, data)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "proof verify: %v\n", err)
		return exitError
	}
	return exitOK
}

// proofSigner opens the configuration, the master key and the database
// like rotate-master-key, and returns the signer with a cleanup function.
func proofSigner(ctx context.Context, stderr io.Writer) (*proof.Signer, func(), error) {
	cfg, err := config.FromEnvironment()
	if err != nil {
		return nil, nil, err
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	keys, err := masterkey.Load(cfg)
	if err != nil {
		return nil, nil, err
	}
	db, err := app.OpenDatabase(ctx, cfg, logger)
	if err != nil {
		keys.Close()
		return nil, nil, err
	}
	closeAll := func() { _ = db.Close(); keys.Close() }
	if _, err := masterkey.Check(ctx, db, keys, nil, time.Now()); err != nil {
		closeAll()
		return nil, nil, err
	}
	return proof.NewSigner(db, masterkey.NewVault(db, keys, nil), audit.New(db), nil, logger), closeAll, nil
}

// runProofKeys lists the signing keys.
func runProofKeys(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("proof keys", stderr)
	if code, ok := parseFlags(fs, args, stderr); !ok {
		return code
	}
	ctx := context.Background()
	signer, closeAll, err := proofSigner(ctx, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "proof keys: %v\n", err)
		return exitError
	}
	defer closeAll()
	keys, err := signer.Keys(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "proof keys: %v\n", err)
		return exitError
	}
	if len(keys) == 0 {
		_, _ = fmt.Fprintln(stdout, "No signing key yet: the first one is created with the first proof.")
		return exitOK
	}
	w := bufio.NewWriter(stdout)
	_, _ = fmt.Fprintf(w, "%-32s  %-24s  %-24s  %s\n", "KEY", "CREATED", "RETIRED", "STATE")
	for _, k := range keys {
		retired, state := "-", "active"
		if !k.RetiredAt.IsZero() {
			retired, state = k.RetiredAt.UTC().Format(time.RFC3339), "retired"
		}
		_, _ = fmt.Fprintf(w, "%-32s  %-24s  %-24s  %s\n", k.KeyID, k.CreatedAt.UTC().Format(time.RFC3339), retired, state)
	}
	if err := w.Flush(); err != nil {
		_, _ = fmt.Fprintf(stderr, "proof keys: %v\n", err)
		return exitError
	}
	return exitOK
}

// runProofRetireKey retires the active signing key after confirmation.
func runProofRetireKey(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("proof retire-key", stderr)
	yes := fs.Bool("yes", false, "retire without asking for confirmation")
	if code, ok := parseFlags(fs, args, stderr); !ok {
		return code
	}
	if !*yes {
		if !stdinIsTerminal() {
			_, _ = fmt.Fprintln(stderr, "proof retire-key: not an interactive terminal: pass --yes to confirm")
			return exitUsage
		}
		_, _ = fmt.Fprint(stdout, "Retire the active proof signing key? Its private part is destroyed. [y/N] ")
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			_, _ = fmt.Fprintln(stdout, "Aborted.")
			return exitError
		}
	}
	ctx := context.Background()
	signer, closeAll, err := proofSigner(ctx, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "proof retire-key: %v\n", err)
		return exitError
	}
	defer closeAll()
	k, err := signer.Retire(ctx, proof.CLIActor)
	switch {
	case errors.Is(err, proof.ErrNoActiveKey):
		_, _ = fmt.Fprintln(stderr, "proof retire-key: there is no active signing key (the next proof creates one)")
		return exitError
	case err != nil:
		_, _ = fmt.Fprintf(stderr, "proof retire-key: %v\n", err)
		return exitError
	}
	_, _ = fmt.Fprintf(stdout, "Signing key %s retired and its private part destroyed.\n"+
		"A new key is created at the next proof. The public key stays published, so the proofs it signed stay verifiable.\n", k.ID)
	return exitOK
}
