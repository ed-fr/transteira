package notify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/store"
)

// TestViewOf maps every scan status to the result the mails show, and
// keeps the notion of a delivered file aligned with the store's.
func TestViewOf(t *testing.T) {
	want := map[store.ScanStatus]ScanResult{
		store.ScanPending:             ScanWithheld,
		store.ScanScanning:            ScanWithheld,
		store.ScanClean:               ScanClean,
		store.ScanInfected:            ScanInfected,
		store.ScanNotScannedTooLarge:  ScanTooLarge,
		store.ScanNotScannedEncrypted: ScanEncrypted,
		store.ScanNotScannedDisabled:  ScanDisabled,
		store.ScanError:               ScanWithheld,
	}
	exp := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	d := store.TransferDetails{
		Transfer: store.Transfer{
			ID: "trf_x", Language: "fr", SenderEmail: "alice@entity-a.example.com", Message: "m",
			ExpiresAt: exp, PasswordHash: "h",
		},
		Recipients: []string{"bob@customer.example.net"},
	}
	var statuses []store.ScanStatus
	for s := range want {
		statuses = append(statuses, s)
		d.Files = append(d.Files, store.TransferFile{Name: string(s), Size: 3, SHA256: "ab", ScanStatus: s, ScanSignature: "sig-" + string(s)})
	}
	v := ViewOf(d)
	if v.ID != "trf_x" || v.Language != "fr" || v.SenderEmail != d.SenderEmail || v.Message != "m" ||
		!v.ExpiresAt.Equal(exp) || !v.PasswordProtected || len(v.Recipients) != 1 || len(v.Files) != len(statuses) {
		t.Fatalf("view %+v", v)
	}
	if v.ConfidentialityLabels != nil {
		t.Errorf("labels without level = %v", v.ConfidentialityLabels)
	}
	d.ConfidentialityLevel = "secret"
	d.ConfidentialityLabel = map[string]string{"fr": "Secret", "en": "Secret EN"}
	lv := ViewOf(d)
	if lv.ConfidentialityLabels["en"] != "Secret EN" || len(lv.ConfidentialityLabels) != 2 {
		t.Errorf("labels = %v", lv.ConfidentialityLabels)
	}
	lv.ConfidentialityLabels["en"] = "changed"
	if d.ConfidentialityLabel["en"] != "Secret EN" {
		t.Error("the view shares the labels of the transfer")
	}
	for i, s := range statuses {
		f := v.Files[i]
		if f.Scan != want[s] || f.Name != string(s) || f.Size != 3 || f.SHA256 != "ab" {
			t.Errorf("%s mapped to %+v, want %d", s, f, want[s])
		}
		if f.Scan.Delivered() != s.Deliverable() {
			t.Errorf("%s: delivered=%v, store deliverable=%v", s, f.Scan.Delivered(), s.Deliverable())
		}
		if (f.Signature != "") != (s == store.ScanInfected) {
			t.Errorf("%s: signature %q", s, f.Signature)
		}
	}
}

// TestViewOfReply marks a reply transfer with the creation time of its
// original, read from the original identifier so that it survives the
// purge of the original; a transfer that is not a reply has none.
func TestViewOfReply(t *testing.T) {
	created := time.Date(2026, 10, 20, 9, 30, 0, 0, time.UTC)
	origID := id.NewGenerator(func() time.Time { return created }, nil)
	orig, err := origID.New(id.Transfer)
	if err != nil {
		t.Fatal(err)
	}
	if v := ViewOf(store.TransferDetails{}); v.ReplyTo != nil || !v.replyCreatedAt().IsZero() {
		t.Errorf("not a reply: %+v", v.ReplyTo)
	}
	reply := store.Transfer{ID: "trf_r", SenderKind: store.DepositorReply, ReplyToTransferID: orig, CreatedAt: created.AddDate(0, 0, 3)}
	v := ViewOf(store.TransferDetails{Transfer: reply})
	if v.ReplyTo == nil || !v.ReplyTo.OriginalCreatedAt.Equal(created) || !v.replyCreatedAt().Equal(created) {
		t.Errorf("reply view %+v", v.ReplyTo)
	}
	// An identifier that does not parse (never stored) keeps the warning,
	// dated with the reply itself.
	reply.ReplyToTransferID = "trf_bad"
	if v := ViewOf(store.TransferDetails{Transfer: reply}); v.ReplyTo == nil || !v.ReplyTo.OriginalCreatedAt.Equal(reply.CreatedAt) {
		t.Errorf("fallback view %+v", v.ReplyTo)
	}
}

// TestFolderPathInMails joins the folder of a file to its name in the
// mail lists (delivered, infected and withheld files), and ViewOf carries
// the folder of the store file.
func TestFolderPathInMails(t *testing.T) {
	v := ViewOf(store.TransferDetails{Files: []store.TransferFile{
		{Path: "plans/2026", Name: "a.pdf", ScanStatus: store.ScanClean},
		{Name: "b.pdf", ScanStatus: store.ScanClean},
	}})
	if v.Files[0].Path != "plans/2026" || v.Files[1].Path != "" {
		t.Fatalf("view files = %+v", v.Files)
	}
	for _, tc := range []struct {
		f    FileView
		want string
	}{
		{FileView{Name: "a.pdf"}, "a.pdf"},
		{FileView{Path: "plans/2026", Name: "a.pdf"}, "plans/2026/a.pdf"},
		{FileView{Path: "pl\u202eans\nx", Name: "a\u200b.pdf"}, "plans x/a.pdf"},
	} {
		if got := tc.f.displayName(); got != tc.want {
			t.Errorf("displayName(%+v) = %q, want %q", tc.f, got, tc.want)
		}
	}

	e := newEnv(t)
	tr := testTransfer()
	tr.Language = "en"
	tr.Files[0].Path = "plans/2026"
	tr.Files[2].Path = "suspect"
	tr.Files[3].Path = "archives/old"
	ctx := context.Background()
	jobs, err := e.n.RecipientJobs(ctx, e.t, tr, testLink)
	if err != nil || len(jobs) == 0 || !strings.Contains(jobs[0].Message.Text, "plans/2026/report.pdf") ||
		!strings.Contains(jobs[0].Message.HTML, "plans/2026/report.pdf") {
		t.Errorf("recipient mail: %v\n%+v", err, jobs)
	}
	j, err := e.n.FileProblems(ctx, e.t, tr)
	if err != nil || !strings.Contains(j.Message.Text, "suspect/eicar.com") ||
		!strings.Contains(j.Message.Text, "archives/old/locked.zip") {
		t.Errorf("problems mail: %v\n%s", err, j.Message.Text)
	}
}
