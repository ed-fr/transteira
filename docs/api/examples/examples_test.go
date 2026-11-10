// Package examples_test checks the API example scripts of this folder against
// the reference implementation of the secret format (internal/tte2) and its
// shared test vectors (internal/tte2/testdata/vectors.json, e2e-format.md
// section 3.3): secret-create.mjs with the local Node.js, secret-create.ps1
// with PowerShell in a pinned Docker image.
package examples_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/internal/tte2"
)

// powershellImage is the pinned PowerShell image of the self-test (tag and
// digest): PowerShell 7.5 on .NET 9.
const powershellImage = "mcr.microsoft.com/powershell:7.5-ubuntu-24.04@sha256:042240d57ec9e47e511033b92625a8d95875ee5860af3015992c248b58a8be81"

// selfTestOK is the line both scripts print when every vector matches.
const selfTestOK = "self-test: ok ("

// vectorsPath returns the absolute path of the shared test vectors.
func vectorsPath(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "..", "internal", "tte2", "testdata", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
	return p
}

// requireTool skips the test when name is not installed, or fails it under
// TT_TEST_REQUIRE_POSTGRES=1 (make check), which needs Docker and Node.js
// anyway (test database, web build).
func requireTool(t *testing.T, name string, args ...string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err == nil && len(args) > 0 {
		err = exec.Command(path, args...).Run()
	}
	if err != nil {
		msg := name + " is not available (" + err.Error() + "): the example script is not checked"
		if os.Getenv("TT_TEST_REQUIRE_POSTGRES") == "1" {
			t.Fatal(msg)
		}
		t.Skip("SKIPPED: " + msg)
	}
	return path
}

// run runs cmd and returns its standard output, failing with its standard
// error.
func run(t *testing.T, cmd *exec.Cmd) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s: %v\nstdout:\n%s\nstderr:\n%s", strings.Join(cmd.Args, " "), err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

// TestNodeSelfTest: secret-create.mjs reproduces every positive and negative
// secret vector.
func TestNodeSelfTest(t *testing.T) {
	t.Parallel()
	node := requireTool(t, "node")
	out := run(t, exec.Command(node, "secret-create.mjs", "self-test", vectorsPath(t)))
	if !strings.HasPrefix(out, selfTestOK) {
		t.Fatalf("output %q, want %q...", out, selfTestOK)
	}
}

// TestPowerShellSelfTest: secret-create.ps1 reproduces every positive and
// negative secret vector, in the pinned PowerShell image without network.
func TestPowerShellSelfTest(t *testing.T) {
	t.Parallel()
	docker := requireTool(t, "docker", "info")
	examples, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	vectors := vectorsPath(t)
	cmd := exec.Command(docker, "run", "--rm", "--network", "none",
		"-v", examples+":/examples:ro",
		"-v", filepath.Dir(vectors)+":/vectors:ro",
		powershellImage,
		"pwsh", "-NoProfile", "-NonInteractive", "-File", "/examples/secret-create.ps1",
		"self-test", "-Vectors", "/vectors/"+filepath.Base(vectors))
	out := run(t, cmd)
	if !strings.HasPrefix(out, selfTestOK) {
		t.Fatalf("output %q, want %q...", out, selfTestOK)
	}
}

// sealed is the output of secret-create.mjs seal.
type sealed struct {
	FragmentKey string `json:"fragmentKey"`
	Body        struct {
		EncryptedText string `json:"encryptedText"`
		KeyVerifier   string `json:"keyVerifier"`
		Verifier      string `json:"verifier"`
		Passphrase    *struct {
			KDF        string `json:"kdf"`
			Iterations int    `json:"iterations"`
			Salt       string `json:"salt"`
		} `json:"passphrase"`
	} `json:"body"`
}

// TestNodeSealOpensInGo: a secret sealed by secret-create.mjs with a random
// key opens with internal/tte2, and its verifiers match the proofs derived
// in Go, with and without a passphrase.
func TestNodeSealOpensInGo(t *testing.T) {
	t.Parallel()
	node := requireTool(t, "node")
	const text = "Code d'accès : 4F7#kp9\nÉté, 日本語, 😀."
	// The file ends with a line break, which the script drops (only that one).
	const passphrase = "Café au lait ☕"
	passFile := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(passFile, []byte(passphrase+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, withPassphrase := range []bool{false, true} {
		cmd := exec.Command(node, "secret-create.mjs", "seal")
		cmd.Stdin = strings.NewReader(text)
		cmd.Env = append(os.Environ(), "TT_PASSPHRASE_FILE=")
		pass := ""
		if withPassphrase {
			cmd.Env = append(cmd.Env, "TT_PASSPHRASE_FILE="+passFile)
			pass = passphrase
		}
		var s sealed
		if err := json.Unmarshal([]byte(run(t, cmd)), &s); err != nil {
			t.Fatal(err)
		}
		key, err := tte2.DecodeKey(s.FragmentKey)
		if err != nil {
			t.Fatalf("fragment key %q: %v", s.FragmentKey, err)
		}
		var d tte2.PassphraseDescriptor
		if (s.Body.Passphrase != nil) != withPassphrase {
			t.Fatalf("passphrase descriptor %+v, want one: %v", s.Body.Passphrase, withPassphrase)
		}
		if p := s.Body.Passphrase; p != nil {
			salt, err := tte2.DecodePassphraseSalt(p.Salt)
			if err != nil {
				t.Fatal(err)
			}
			d = tte2.PassphraseDescriptor{KDF: p.KDF, Iterations: p.Iterations, Salt: salt}
		}
		root, err := tte2.DeriveSecretKey(key, pass, d)
		if err != nil {
			t.Fatal(err)
		}
		got, err := tte2.OpenSecret(root, s.Body.EncryptedText)
		if err != nil || got != text {
			t.Fatalf("OpenSecret = %q, %v; want %q", got, err, text)
		}
		keyProof, err := tte2.SecretKeyProof(key)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := tte2.SecretProof(root)
		if err != nil {
			t.Fatal(err)
		}
		for name, pair := range map[string][2]string{
			"keyVerifier": {s.Body.KeyVerifier, tte2.EncodeProof(tte2.SecretVerifier(keyProof))},
			"verifier":    {s.Body.Verifier, tte2.EncodeProof(tte2.SecretVerifier(proof))},
		} {
			if pair[0] != pair[1] {
				t.Errorf("passphrase %v: %s %s, want %s", withPassphrase, name, pair[0], pair[1])
			}
		}
		// The wrong passphrase must not open it.
		if withPassphrase {
			wrong, err := tte2.DeriveSecretKey(key, passphrase+"!", d)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tte2.OpenSecret(wrong, s.Body.EncryptedText); !errors.Is(err, tte2.ErrAuth) {
				t.Errorf("open with a wrong passphrase: %v, want ErrAuth", err)
			}
		}
	}
}
