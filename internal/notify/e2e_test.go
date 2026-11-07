package notify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/store"
)

// e2eSecretMessage stands for the message of an end-to-end encrypted
// transfer: it must never reach a mail, whatever the caller passes.
const e2eSecretMessage = "SECRET-CIPHERTEXT-MESSAGE"

func e2eTransfer() TransferView {
	return TransferView{
		ID:          "tr_e2e",
		SenderEmail: "alice@entity-a.example.com",
		Recipients:  []string{"bob@example.com"},
		Message:     e2eSecretMessage,
		ExpiresAt:   testNow.Add(7 * 24 * time.Hour),
		E2E:         true,
		Files: []FileView{
			{Name: "file-1.tte2", Size: 2 << 20, SHA256: strings.Repeat("ab", 32), Scan: ScanE2E},
			{Name: "file-2.tte2", Size: 1 << 20, SHA256: strings.Repeat("cd", 32), Scan: ScanE2E},
		},
	}
}

// TestE2EMails checks the mails of an end-to-end encrypted transfer, in
// both languages: no message, no generic name, the key-by-another-channel
// and not-analyzed notices, the digests labeled as the ciphertext's.
func TestE2EMails(t *testing.T) {
	for _, tc := range []struct {
		lang   string
		wants  []string
		sender []string
	}{
		{"fr", []string{
			"Fichier chiffré 1 (2,0\u00a0Mo)", "Fichier chiffré 2", "chiffré de bout en bout", "par un autre canal",
			"n'ont pas été analysés par l'antivirus", "SHA-256 du fichier chiffré : " + strings.Repeat("ab", 32),
		}, []string{"aucune clé de déchiffrement", "n'ont pas été analysés"}},
		{"en", []string{
			"Encrypted file 1", "Encrypted file 2", "end-to-end encrypted", "through another channel",
			"not analyzed by the antivirus", "SHA-256 of the encrypted file: " + strings.Repeat("cd", 32),
		}, []string{"contains no decryption key", "not analyzed by the antivirus"}},
	} {
		t.Run(tc.lang, func(t *testing.T) {
			e := newEnv(t)
			e.t.DefaultLanguage = tc.lang
			tr := e2eTransfer()
			ctx := context.Background()
			var jobs []string
			rj, err := e.n.RecipientJobs(ctx, e.t, tr, testLink)
			if err != nil {
				t.Fatal(err)
			}
			if len(rj) != 1 {
				t.Fatalf("%d recipient jobs", len(rj))
			}
			for _, w := range tc.wants {
				if !strings.Contains(rj[0].Message.Text, w) {
					t.Errorf("notification lacks %q:\n%s", w, rj[0].Message.Text)
				}
			}
			if !strings.Contains(rj[0].Message.Text, testLink) || strings.Contains(rj[0].Message.Text, "#k=") {
				t.Errorf("link or key in the notification:\n%s", rj[0].Message.Text)
			}
			jobs = append(jobs, build(t, rj[0]), rj[0].Message.Text, rj[0].Message.HTML)

			// The per-recipient mails carry the same notices (regression: the flag was dropped).
			pj, err := e.n.PerRecipientJobs(ctx, e.t, tr, []RecipientLink{{Email: "r1@example.org", Link: testLink}})
			if err != nil || len(pj) != 1 {
				t.Fatalf("per-recipient jobs: %v (%d)", err, len(pj))
			}
			for _, w := range tc.wants[2:4] {
				if !strings.Contains(pj[0].Message.Text, w) {
					t.Errorf("per-recipient notification lacks %q:\n%s", w, pj[0].Message.Text)
				}
			}

			sc, err := e.n.SenderConfirmation(ctx, e.t, tr, testLink)
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range tc.sender {
				if !strings.Contains(sc.Message.Text, w) {
					t.Errorf("confirmation lacks %q:\n%s", w, sc.Message.Text)
				}
			}
			jobs = append(jobs, build(t, sc), sc.Message.Text, sc.Message.HTML)

			fd, err := e.n.FirstDownload(ctx, e.t, tr, testNow, time.Time{})
			if err != nil {
				t.Fatal(err)
			}
			jobs = append(jobs, build(t, fd), fd.Message.Text, fd.Message.HTML)
			if !strings.Contains(fd.Message.Text, tc.wants[1]) {
				t.Errorf("first download lists no generic file:\n%s", fd.Message.Text)
			}

			er, err := e.n.ExpiryReminderJobs(ctx, e.t, tr, testLinks()[:1], false)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(er[0].Message.Text, tc.wants[2]) || !strings.Contains(er[0].Message.Text, tc.wants[3]) {
				t.Errorf("reminder lacks the key notice:\n%s", er[0].Message.Text)
			}
			jobs = append(jobs, build(t, er[0]), er[0].Message.Text, er[0].Message.HTML)

			ns, err := e.n.FileNotScanned(ctx, e.t, tr)
			if err != nil {
				t.Fatal(err)
			}
			jobs = append(jobs, build(t, ns), ns.Message.Text, ns.Message.HTML)

			for i, raw := range jobs {
				for _, bad := range []string{e2eSecretMessage, "file-1.tte2", "file-2.tte2"} {
					if strings.Contains(raw, bad) {
						t.Errorf("mail %d leaks %q", i, bad)
					}
				}
			}
		})
	}
}

// TestE2EMailsRegular checks that the notice stays out of a regular
// transfer.
func TestE2EMailsRegular(t *testing.T) {
	e := newEnv(t)
	rj, err := e.n.RecipientJobs(context.Background(), e.t, testTransfer(), testLink)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rj[0].Message.Text, "bout en bout") || !strings.Contains(rj[0].Message.Text, "See you") {
		t.Errorf("regular notification:\n%s", rj[0].Message.Text)
	}
}

// TestViewOfE2E maps the end-to-end files and drops the message.
func TestViewOfE2E(t *testing.T) {
	d := store.TransferDetails{
		Transfer: store.Transfer{E2E: true, Message: "x"},
		Files: []store.TransferFile{
			{Name: "file-1.tte2", Size: 60, SHA256: strings.Repeat("ab", 32), ScanStatus: store.ScanNotScannedE2E},
		},
	}
	v := ViewOf(d)
	if !v.E2E || v.Message != "" || len(v.Files) != 1 || v.Files[0].Scan != ScanE2E || !v.Files[0].Scan.Delivered() {
		t.Errorf("view %+v", v)
	}
	if err := checkScans(v.Files); err != nil {
		t.Errorf("checkScans: %v", err)
	}
}
