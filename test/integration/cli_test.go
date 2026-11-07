package integration_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/antivirus/antivirustest"
	"github.com/ed-fr/transteira/internal/cli/client"
	"github.com/ed-fr/transteira/internal/cli/download"
	"github.com/ed-fr/transteira/internal/cli/upload"
	"github.com/ed-fr/transteira/internal/proofverify"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tte2"
)

// Integration tests of the command-line client libraries (V2 step 9;
// internal/cli/client, upload, download and internal/proofverify) against
// the real server, through a TLS front that keeps the Host (see
// cli_helpers_test.go). The binary itself is not driven here.

const cliChunk = 1 << 20

// cliEnv is a running server with an API token of tenant A and a client
// that reaches it through the TLS front.
type cliEnv struct {
	*opsEnv
	front  *cliFront
	c      *client.Client
	sender string
	token  string
}

// startCLI starts the server, creates an API token for the front's IP and
// builds the client.
func startCLI(t *testing.T, e storetest.Engine) *cliEnv {
	t.Helper()
	o := startOps(t, e)
	_, secret := o.sa.createToken(t, o.tid, "command line", []string{scriptNet}, nil)
	front := startCLIFront(t, o.server, scriptIP)
	sender := uniqueEmail(t, "cli", domainA)
	return &cliEnv{
		opsEnv: o, front: front, sender: sender, token: secret,
		c: front.newClient(t, hostA, secret, sender),
	}
}

// uploadOpts returns small-chunk options with a private state file.
func (ce *cliEnv) uploadOpts(t *testing.T, recipient string, paths ...string) upload.Options {
	t.Helper()
	return upload.Options{
		Paths: paths, Recipients: []string{recipient}, ExpiryDays: 7, ChunkSize: cliChunk,
		StatePath: filepath.Join(t.TempDir(), "state.json"), PollInterval: 20 * time.Millisecond,
	}
}

// link returns the parsed download link of recipient for the transfer.
func (ce *cliEnv) link(t *testing.T, trfID, recipient string) download.Link {
	t.Helper()
	l, err := download.ParseLink(ce.recipientLink(t, hostA, trfID, recipient))
	if err != nil {
		t.Fatalf("ParseLink: %v", err)
	}
	return l
}

// readFileOrFail returns the content of path.
func readFileOrFail(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestCLIUploadDownloadFolder: a folder and a loose file are sent with an API
// token, then downloaded file by file and as an archive; the digests equal the
// originals and the folder tree is kept.
func TestCLIUploadDownloadFolder(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		ce := startCLI(t, e)
		src := t.TempDir()
		files := map[string][]byte{
			"project/readme.txt":     []byte("hello from the folder"),
			"project/data/big.bin":   seededBytes(t, 11, 2*cliChunk+4321),
			"project/data/deep/x.md": seededBytes(t, 12, 70000),
			"solo.bin":               seededBytes(t, 13, cliChunk+17),
		}
		writeTree(t, src, files)
		rcpt := uniqueEmail(t, "rcpt", "example.net")
		opts := ce.uploadOpts(t, rcpt, filepath.Join(src, "project"), filepath.Join(src, "solo.bin"))
		res, err := upload.Run(context.Background(), ce.c, opts)
		if err != nil {
			t.Fatalf("upload.Run: %v", err)
		}
		if res.Status != "available" || len(res.Files) != 4 {
			t.Fatalf("result = %+v, want an available transfer of 4 files", res)
		}
		for _, f := range res.Files {
			rel := f.Name
			if f.Path != "" {
				rel = f.Path + "/" + f.Name
			}
			if want := sha256Hex(files[rel]); f.SHA256 != want || f.ScanStatus != "clean" {
				t.Errorf("uploaded %s: sha256 %s status %s, want %s clean", rel, f.SHA256, f.ScanStatus, want)
			}
		}
		if _, err := os.Stat(opts.StatePath); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the state file remains after a success (%v)", err)
		}

		link := ce.link(t, res.TransferID, rcpt)
		out := t.TempDir()
		dres, err := download.Run(context.Background(), ce.c, download.Options{Link: link, Output: out})
		if err != nil {
			t.Fatalf("download.Run: %v", err)
		}
		if dres.Sender != ce.sender || len(dres.Files) != 4 {
			t.Errorf("download result = %+v", dres)
		}
		for rel, want := range files {
			if got := readFileOrFail(t, filepath.Join(out, filepath.FromSlash(rel))); !bytes.Equal(got, want) {
				t.Errorf("%s: downloaded %d bytes, differ from the %d sent", rel, len(got), len(want))
			}
		}

		// File by file, selected by identifier.
		for _, f := range dres.Files {
			single := t.TempDir()
			r, err := download.Run(context.Background(), ce.c, download.Options{Link: link, Output: single, Files: []string{f.ID}})
			if err != nil {
				t.Fatalf("download of %s: %v", f.ID, err)
			}
			n := 0
			for _, rf := range r.Files {
				if rf.Skipped {
					continue
				}
				n++
				if got := sha256Hex(readFileOrFail(t, rf.Path)); got != rf.SHA256 {
					t.Errorf("file %s: sha256 %s, want %s", rf.Path, got, rf.SHA256)
				}
			}
			if n != 1 {
				t.Errorf("selecting %s wrote %d files, want 1", f.ID, n)
			}
		}

		// The server archive.
		ares, err := download.Run(context.Background(), ce.c, download.Options{Link: link, Output: t.TempDir(), Archive: true})
		if err != nil {
			t.Fatalf("download archive: %v", err)
		}
		zr, err := zip.OpenReader(ares.Archive)
		if err != nil {
			t.Fatalf("open archive: %v", err)
		}
		defer func() { _ = zr.Close() }()
		if len(zr.File) != 4 {
			t.Errorf("archive holds %d entries, want 4", len(zr.File))
		}
		for _, zf := range zr.File {
			rc, err := zf.Open()
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(rc)
			_ = rc.Close()
			if err != nil {
				t.Fatal(err)
			}
			want, ok := files[zf.Name]
			if !ok {
				t.Errorf("archive entry %q is not a file sent (tree not kept?)", zf.Name)
				continue
			}
			if !bytes.Equal(data, want) {
				t.Errorf("archive entry %q differs from the original", zf.Name)
			}
		}
	})
}

// TestCLIResume: a PATCH cut by the network resumes in the process; then an
// interrupted run is resumed by a second run with the same state file, on the
// same transfer.
func TestCLIResume(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		ce := startCLI(t, e)
		src := t.TempDir()
		content := seededBytes(t, 21, 3*cliChunk+999)
		writeTree(t, src, map[string][]byte{"cut.bin": content})
		rcpt := uniqueEmail(t, "rcpt", "example.net")

		// 1. Cut inside the first PATCH.
		ce.front.cutAfter.Store(300 << 10)
		res, err := upload.Run(context.Background(), ce.c, ce.uploadOpts(t, rcpt, filepath.Join(src, "cut.bin")))
		if err != nil {
			t.Fatalf("upload.Run after a cut: %v", err)
		}
		if ce.front.cutAfter.Load() != 0 {
			t.Errorf("the cut was not triggered")
		}
		if ids := ce.front.createdIDs(); len(ids) != 1 || ids[0] != res.TransferID {
			t.Errorf("created %v, want only %s", ids, res.TransferID)
		}
		dl, err := download.Run(context.Background(), ce.c, download.Options{Link: ce.link(t, res.TransferID, rcpt), Output: t.TempDir()})
		if err != nil || sha256Hex(readFileOrFail(t, dl.Files[0].Path)) != sha256Hex(content) {
			t.Fatalf("download after a cut: %v", err)
		}

		// 2. Interrupted run, then a new run with the same state file.
		src2 := t.TempDir()
		content2 := seededBytes(t, 22, 3*cliChunk+5)
		writeTree(t, src2, map[string][]byte{"again.bin": content2})
		rcpt2 := uniqueEmail(t, "rcpt", "example.net")
		opts := ce.uploadOpts(t, rcpt2, filepath.Join(src2, "again.bin"))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		opts.Progress = func(p upload.Progress) {
			if p.Phase == upload.PhaseUpload && p.Done >= cliChunk {
				cancel()
			}
		}
		if _, err := upload.Run(ctx, ce.c, opts); err == nil {
			t.Fatal("the canceled upload succeeded")
		}
		if _, err := os.Stat(opts.StatePath); err != nil {
			t.Fatalf("no state file after the interruption: %v", err)
		}
		first := ce.front.createdIDs()
		if len(first) != 2 {
			t.Fatalf("created %v after the interruption, want 2 transfers in all", first)
		}
		opts.Progress = nil
		res2, err := upload.Run(context.Background(), ce.c, opts)
		if err != nil {
			t.Fatalf("resumed upload.Run: %v", err)
		}
		if res2.TransferID != first[1] {
			t.Errorf("resumed transfer %s, want the interrupted %s", res2.TransferID, first[1])
		}
		if ids := ce.front.createdIDs(); len(ids) != 2 {
			t.Errorf("created %v, the resume must not create a transfer", ids)
		}
		dl2, err := download.Run(context.Background(), ce.c, download.Options{Link: ce.link(t, res2.TransferID, rcpt2), Output: t.TempDir()})
		if err != nil || sha256Hex(readFileOrFail(t, dl2.Files[0].Path)) != sha256Hex(content2) {
			t.Fatalf("download after the resume: %v", err)
		}
	})
}

// TestCLIEndToEnd: an end-to-end encrypted deposit downloads identically with
// the key, is refused with another key, and the server only knows generic
// names.
func TestCLIEndToEnd(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		ce := startCLI(t, e)
		ce.setE2EPolicy(t, "allowed")
		src := t.TempDir()
		files := map[string][]byte{
			"secret-plans/q3-budget.xlsx": seededBytes(t, 31, cliChunk+123),
			"secret-plans/notes.txt":      []byte("very private notes"),
		}
		writeTree(t, src, files)
		const message = "The acquisition plan: do not forward"
		rcpt := uniqueEmail(t, "rcpt", "example.net")
		opts := ce.uploadOpts(t, rcpt, filepath.Join(src, "secret-plans"))
		opts.E2E, opts.Message = true, message
		res, err := upload.Run(context.Background(), ce.c, opts)
		if err != nil {
			t.Fatalf("upload.Run: %v", err)
		}
		if res.Key == "" {
			t.Fatal("no end-to-end key in the result")
		}
		ce.secret(res.Key)

		// The server holds generic names and no plaintext message.
		script := ce.scriptClient(ce.token, scriptIP)
		view := script.mustGet(t, res.TransferID)
		if !view.EndToEndEncrypted || view.Message != "" || len(view.Files) != 2 {
			t.Fatalf("server view = %+v", view)
		}
		for i, f := range view.Files {
			if f.Name != e2eName(i) {
				t.Errorf("file %d is named %q on the server, want %s", i, f.Name, e2eName(i))
			}
		}
		raw := script.getTransfer(t, res.TransferID)
		for _, leak := range []string{"q3-budget", "notes.txt", "secret-plans", message} {
			if strings.Contains(string(raw.body), leak) {
				t.Errorf("the server view leaks %q", leak)
			}
		}

		link := ce.link(t, res.TransferID, rcpt)
		out := t.TempDir()
		dres, err := download.Run(context.Background(), ce.c, download.Options{
			Link: link, Output: out, Key: func() (string, error) { return res.Key, nil },
		})
		if err != nil {
			t.Fatalf("download.Run: %v", err)
		}
		if dres.Message != message || !dres.EndToEnd {
			t.Errorf("message %q end-to-end %v, want %q", dres.Message, dres.EndToEnd, message)
		}
		for rel, want := range files {
			if got := readFileOrFail(t, filepath.Join(out, filepath.FromSlash(rel))); !bytes.Equal(got, want) {
				t.Errorf("%s: decrypted content differs", rel)
			}
		}

		// Wrong key.
		other, err := tte2.NewKey()
		if err != nil {
			t.Fatal(err)
		}
		otherB64, err := tte2.EncodeKey(other)
		if err != nil {
			t.Fatal(err)
		}
		_, err = download.Run(context.Background(), ce.c, download.Options{
			Link: link, Output: t.TempDir(), Key: func() (string, error) { return otherB64, nil },
		})
		if !errors.Is(err, download.ErrWrongKey) {
			t.Errorf("download with another key: %v, want ErrWrongKey", err)
		}
		_, err = download.Run(context.Background(), ce.c, download.Options{Link: link, Output: t.TempDir()})
		if !errors.Is(err, download.ErrKeyRequired) {
			t.Errorf("download without key: %v, want ErrKeyRequired", err)
		}
	})
}

// TestCLIPasswordAndVerification: a wrong transfer password then the right
// one, and a recipient verification with the code read from Mailpit.
func TestCLIPasswordAndVerification(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		ce := startCLI(t, e)
		src := t.TempDir()
		content := []byte("protected content")
		writeTree(t, src, map[string][]byte{"p.txt": content})

		rcpt := uniqueEmail(t, "rcpt", "example.net")
		opts := ce.uploadOpts(t, rcpt, filepath.Join(src, "p.txt"))
		opts.Password, opts.HasPassword = "correct horse", true
		res, err := upload.Run(context.Background(), ce.c, opts)
		if err != nil {
			t.Fatalf("upload.Run: %v", err)
		}
		link := ce.link(t, res.TransferID, rcpt)
		calls := 0
		dres, err := download.Run(context.Background(), ce.c, download.Options{
			Link: link, Output: t.TempDir(),
			Password: func() (string, error) {
				calls++
				if calls == 1 {
					return "wrong guess", nil
				}
				return "correct horse", nil
			},
		})
		if err != nil || calls != 2 {
			t.Fatalf("password download: %v after %d password calls, want success after 2", err, calls)
		}
		if !bytes.Equal(readFileOrFail(t, dres.Files[0].Path), content) {
			t.Error("password download: content differs")
		}
		// A fresh client holds no download grant (the first one keeps its cookie).
		fresh := ce.front.newClient(t, hostA, ce.token, ce.sender)
		_, err = download.Run(context.Background(), fresh, download.Options{Link: link, Output: t.TempDir()})
		if !errors.Is(err, download.ErrPasswordRequired) {
			t.Errorf("download without password: %v, want ErrPasswordRequired", err)
		}

		// Recipient verification.
		rcpt2 := uniqueEmail(t, "rcpt", "example.net")
		opts2 := ce.uploadOpts(t, rcpt2, filepath.Join(src, "p.txt"))
		opts2.VerifyRecipients = true
		res2, err := upload.Run(context.Background(), ce.c, opts2)
		if err != nil {
			t.Fatalf("upload.Run (verification): %v", err)
		}
		link2 := ce.link(t, res2.TransferID, rcpt2)
		_, err = download.Run(context.Background(), ce.front.newClient(t, hostA, ce.token, ce.sender), download.Options{Link: link2, Output: t.TempDir()})
		if !errors.Is(err, download.ErrCodeRequired) {
			t.Errorf("download without a code callback: %v, want ErrCodeRequired", err)
		}
		var masked string
		dres2, err := download.Run(context.Background(), ce.c, download.Options{
			Link: link2, Output: t.TempDir(),
			Code: func(m string) (string, error) {
				masked = m
				return ce.waitCode(t, rcpt2, 1), nil
			},
		})
		if err != nil {
			t.Fatalf("verified download: %v", err)
		}
		if masked == "" || strings.Contains(masked, strings.Split(rcpt2, "@")[0]) {
			t.Errorf("masked address %q, want a masked one", masked)
		}
		if !bytes.Equal(readFileOrFail(t, dres2.Files[0].Path), content) {
			t.Error("verified download: content differs")
		}
	})
}

// TestCLILinkOnly: a link-only transfer returns its link, which downloads.
func TestCLILinkOnly(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		ce := startCLI(t, e)
		ce.setLinkOnly(t, true)
		src := t.TempDir()
		content := seededBytes(t, 41, 100000)
		writeTree(t, src, map[string][]byte{"l.bin": content})
		opts := ce.uploadOpts(t, "", filepath.Join(src, "l.bin"))
		opts.Recipients, opts.LinkOnly = nil, true
		res, err := upload.Run(context.Background(), ce.c, opts)
		if err != nil {
			t.Fatalf("upload.Run: %v", err)
		}
		if res.Link == "" {
			t.Fatal("no link in the result")
		}
		link, err := download.ParseLink(res.Link)
		if err != nil {
			t.Fatalf("ParseLink(%q): %v", res.Link, err)
		}
		dres, err := download.Run(context.Background(), ce.c, download.Options{Link: link, Output: t.TempDir()})
		if err != nil {
			t.Fatalf("download.Run: %v", err)
		}
		if !bytes.Equal(readFileOrFail(t, dres.Files[0].Path), content) {
			t.Error("link-only download: content differs")
		}
	})
}

// TestCLIInfected: an infected file gives ErrRejected.
func TestCLIInfected(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		ce := startCLI(t, e)
		src := t.TempDir()
		writeTree(t, src, map[string][]byte{"invoice.exe": antivirustest.EICAR()})
		opts := ce.uploadOpts(t, uniqueEmail(t, "rcpt", "example.net"), filepath.Join(src, "invoice.exe"))
		res, err := upload.Run(context.Background(), ce.c, opts)
		if !errors.Is(err, upload.ErrRejected) {
			t.Fatalf("upload.Run: %v, want ErrRejected", err)
		}
		if res == nil || len(res.Files) != 1 || res.Files[0].ScanStatus != "infected" {
			t.Errorf("result = %+v, want one infected file", res)
		}
	})
}

// TestCLIInvalidToken: an unknown token stops after one request with a 401.
func TestCLIInvalidToken(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		ce := startCLI(t, e)
		bad := ce.front.newClient(t, hostA, newUnknownSecret(t), ce.sender)
		src := t.TempDir()
		writeTree(t, src, map[string][]byte{"a.txt": []byte("a")})
		before := ce.front.requestCount()
		opts := ce.uploadOpts(t, uniqueEmail(t, "rcpt", "example.net"), filepath.Join(src, "a.txt"))
		_, err := upload.Run(context.Background(), bad, opts)
		var p *client.Problem
		if !errors.As(err, &p) || p.Status != http.StatusUnauthorized {
			t.Fatalf("upload.Run: %v, want a 401 problem", err)
		}
		if n := ce.front.requestCount() - before; n != 1 {
			t.Errorf("%d requests with an invalid token, want exactly 1", n)
		}
	})
}

// TestCLIProofVerify: the deposit proof of a transfer sent by the client
// verifies with the keys of the instance.
func TestCLIProofVerify(t *testing.T) {
	t.Parallel()
	forEngine(t, func(t *testing.T, e storetest.Engine) {
		ce := startCLI(t, e)
		src := t.TempDir()
		writeTree(t, src, map[string][]byte{"proved.txt": []byte("sealed by a proof")})
		rcpt := uniqueEmail(t, "rcpt", "example.net")
		res, err := upload.Run(context.Background(), ce.c, ce.uploadOpts(t, rcpt, filepath.Join(src, "proved.txt")))
		if err != nil {
			t.Fatalf("upload.Run: %v", err)
		}
		path := tenantPath(ce.tid, "/transfers/"+res.TransferID+"/proof?kind=deposit")
		pdf := mustStatus(t, "getTenantTransferProof", ce.sa.call(t, http.MethodGet, path, nil), http.StatusOK)
		keys := ce.do(t, request{method: http.MethodGet, path: pathProofKeys, host: hostA})
		if keys.status != http.StatusOK {
			t.Fatalf("proof keys: %d %s", keys.status, keys.body)
		}
		dir := t.TempDir()
		pdfFile, keysFile := filepath.Join(dir, "proof.pdf"), filepath.Join(dir, "keys.json")
		for p, b := range map[string][]byte{pdfFile: pdf.body, keysFile: keys.body} {
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		st, _, err := proofverify.Verify(context.Background(), proofverify.Options{File: pdfFile, KeysFile: keysFile})
		if err != nil {
			t.Fatalf("proofverify.Verify: %v", err)
		}
		if st.TransferID != res.TransferID || st.SenderEmail != ce.sender {
			t.Errorf("statement = %+v, want transfer %s from %s", st, res.TransferID, ce.sender)
		}
		// A tampered PDF fails.
		bad := bytes.Clone(pdf.body)
		marker := []byte(`"senderEmail":"`)
		i := bytes.Index(bad, marker)
		if i < 0 {
			t.Fatal("statement.json not found in the PDF")
		}
		bad[i+len(marker)] ^= 0x01
		badFile := filepath.Join(dir, "bad.pdf")
		if err := os.WriteFile(badFile, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := proofverify.Verify(context.Background(), proofverify.Options{File: badFile, KeysFile: keysFile}); err == nil {
			t.Error("a tampered proof verifies")
		}
	})
}
