package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/ed-fr/transteira/internal/proofverify"
)

// proofClient downloads the public keys; nil means the default client of
// proofverify. Tests set it.
var proofClient *http.Client

// runProof implements "proof verify".
func runProof(ctx context.Context, args []string, s streams) int {
	if len(args) == 0 || args[0] != "verify" {
		_, _ = fmt.Fprintf(s.err, "Usage: %s proof verify FILE.pdf (--url URL | --keys-file FILE) [--json]\n", prog)
		if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
			return exitUsage
		}
		return usageError(s, "unknown proof command %q", args[0])
	}
	fs := newFlagSet("proof verify", s.err)
	keysFile := fs.String("keys-file", "", "file holding the saved answer of GET /api/v1/proof-keys")
	keysURL := fs.String("url", "", "https URL of the instance (https://FQDN), to download the public keys")
	asJSON := fs.Bool("json", false, "print the verified statement as canonical JSON")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(s.err, "Usage: %s proof verify FILE.pdf (--url URL | --keys-file FILE) [--json]\n", prog)
		fs.PrintDefaults()
	}
	rest, code, ok := parseFlags(fs, args[1:], 1, 1, s.err)
	if !ok {
		return code
	}
	if (*keysFile == "") == (*keysURL == "") {
		fs.Usage()
		return usageError(s, "give exactly one of --url and --keys-file")
	}
	st, data, err := proofverify.Verify(ctx, proofverify.Options{
		File: rest[0], URL: *keysURL, KeysFile: *keysFile, Client: proofClient,
	})
	if err != nil {
		_, _ = fmt.Fprintf(s.err, "%s: proof verify: %s\n", prog, proofverify.Failure(err))
		return exitError
	}
	if *asJSON {
		_, err = s.out.Write(append(data, '\n'))
	} else {
		err = proofverify.PrintStatement(s.out, st, data)
	}
	if err != nil {
		return fail(s, err)
	}
	return exitOK
}
