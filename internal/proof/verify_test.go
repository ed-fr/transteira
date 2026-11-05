package proof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/pdf"
	"github.com/ed-fr/transteira/internal/store"
)

// testKey is a fixed signing key of the unit tests.
var testKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))

const testKID = "psk_01JB0000000000000000000001"

// testPub is the published form of testKey.
func testPub(retired time.Time) PublicKey {
	return PublicKey{KeyID: testKID, PublicKey: testKey.Public().(ed25519.PublicKey), CreatedAt: testStart, RetiredAt: retired}
}

// sampleStatement returns a valid delivery statement signed by testKID.
func sampleStatement() Statement {
	first := "2026-11-05T10:00:00.000Z"
	return Statement{
		SchemaVersion: 1, Kind: store.ProofDelivery, InstanceVersion: "2.0.0",
		Tenant:     StatementTenant{Name: "Entity A (Paris)", FQDN: hostA},
		TransferID: "trf_01JB0000000000000000000002", SenderEmail: aliceNorm, Recipients: []string{carol, dave},
		ConfidentialityLevel: "secret", EndToEndEncrypted: true,
		Files: []StatementFile{
			{Name: "rapport (final) \\ été.pdf", Size: 1000, SHA256: sumA, ScanStatus: "clean"},
			{Name: "日本.bin", Path: "a/b", Size: 1 << 40, SHA256: sumB, ScanStatus: "not_scanned_e2e"},
			{Name: "x", Size: 0, SHA256: sumA, ScanStatus: "future_status"},
		},
		DepositedAt: "2026-11-05T09:30:00.000Z", ExpiresAt: "2026-11-12T09:31:00.000Z", FirstDownloadedAt: &first,
		RecipientDownloads: []RecipientDownload{{Email: carol, FirstDownloadedAt: "2026-11-05T11:00:00.000Z"}},
		KeyID:              testKID,
	}
}

// signed returns the canonical encoding of st and its signature.
func signed(t testing.TB, st Statement) ([]byte, []byte) {
	t.Helper()
	data, err := st.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return data, ed25519.Sign(testKey, data)
}

// writePDF writes a PDF holding the given attachments.
func writePDF(t testing.TB, atts ...pdf.Attachment) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := pdf.Write(&buf, pdf.Document{Title: "x", Attachments: atts}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestRenderVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	st := sampleStatement()
	data, sig := signed(t, st)
	for _, lang := range []string{"fr", "en", "de"} {
		doc, err := Render(st, data, sig, lang, KeysURL(hostA))
		if err != nil {
			t.Fatalf("Render(%s): %v", lang, err)
		}
		got, err := Verify(bytes.NewReader(doc), []PublicKey{{KeyID: "psk_other"}, testPub(time.Time{})}, DefaultVerifyLimit)
		if err != nil {
			t.Fatalf("Verify(%s): %v", lang, err)
		}
		again, _ := got.Marshal()
		if !bytes.Equal(again, data) {
			t.Errorf("verified statement differs: %s", again)
		}
		// The PDF is deterministic and dated by the latest fact.
		doc2, _ := Render(st, data, sig, lang, KeysURL(hostA))
		if !bytes.Equal(doc, doc2) {
			t.Error("Render is not deterministic")
		}
		if !bytes.Contains(doc, []byte("D:20261105110000")) {
			t.Error("creation date is not the latest fact")
		}
		atts, err := pdf.ReadAttachments(bytes.NewReader(doc), DefaultVerifyLimit)
		if err != nil || !bytes.Equal(atts[StatementName], data) || !bytes.Equal(atts[SignatureName], sig) || len(atts) != 2 {
			t.Errorf("attachments = %v, %v", atts, err)
		}
	}
	// Retired after the latest fact: still valid.
	doc, _ := Render(st, data, sig, "en", KeysURL(hostA))
	if _, err := Verify(bytes.NewReader(doc), []PublicKey{testPub(testStart.Add(2 * time.Hour))}, DefaultVerifyLimit); err != nil {
		t.Errorf("Verify(retired later) = %v", err)
	}
}

func TestRenderContent(t *testing.T) {
	t.Parallel()
	st := sampleStatement()
	data, sig := signed(t, st)
	sum := sha256.Sum256(data)
	cases := map[string][]string{
		"fr": {
			"Preuve de remise", "transteira proof verify", "https://" + hostA + "/api/v1/proof-keys", hex.EncodeToString(sum[:]),
			testKID, "Destinataires", "1 099 511 627 776 octets", `non analys\351 \(chiffr\351 de bout en bout\)`,
			"future_status", "a/b/", "Chiffrement de bout en bout", "5 novembre 2026, 10:00:00 UTC", "secret", `rapport \(final\) \\ \351t\351.pdf`, `Fichiers \(3\)`,
		},
		"en": {"Proof of delivery", "Recipients: ", "1,099,511,627,776 bytes", "November 5, 2026, 11:00:00 UTC", "First download by recipient"},
	}
	for lang, wants := range cases {
		doc, err := Render(st, data, sig, lang, KeysURL(hostA))
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range wants {
			if !bytes.Contains(doc, []byte(w)) {
				t.Errorf("%s PDF lacks %q", lang, w)
			}
		}
	}
	// A deposit has no download facts; a large transfer lists its first
	// files only, and the signature block comes before them.
	dep := sampleStatement()
	dep.Kind, dep.FirstDownloadedAt, dep.RecipientDownloads, dep.EndToEndEncrypted, dep.ConfidentialityLevel = store.ProofDeposit, nil, nil, false, ""
	dep.Files = nil
	for i := range MaxVisibleFiles + 5 {
		dep.Files = append(dep.Files, StatementFile{Name: "f" + strings.Repeat("x", i%7) + ".txt", Size: int64(i), SHA256: sumA, ScanStatus: "clean"})
	}
	data, sig = signed(t, dep)
	doc, err := Render(dep, data, sig, "en", KeysURL(hostA))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"Proof of deposit", "5 more files are not listed here", `Files \(305\)`} {
		if !bytes.Contains(doc, []byte(w)) {
			t.Errorf("deposit PDF lacks %q", w)
		}
	}
	if bytes.Contains(doc, []byte("First download")) || bytes.Contains(doc, []byte("End-to-end")) {
		t.Error("deposit PDF shows a download or the E2E notice")
	}
	if _, err := Verify(bytes.NewReader(doc), []PublicKey{testPub(time.Time{})}, DefaultVerifyLimit); err != nil {
		t.Errorf("Verify(large deposit) = %v", err)
	}
}

func TestRenderRejects(t *testing.T) {
	t.Parallel()
	st := sampleStatement()
	data, sig := signed(t, st)
	other := st
	other.SenderEmail = bob
	if _, err := Render(other, data, sig, "en", ""); err == nil {
		t.Error("Render with a mismatched statement succeeded")
	}
	if _, err := Render(st, data, sig[:10], "en", ""); err == nil {
		t.Error("Render with a short signature succeeded")
	}
	big := st
	big.Files = []StatementFile{{Name: "x", Size: 1 << 60, SHA256: sumA, ScanStatus: "clean"}}
	if _, err := Render(big, nil, sig, "en", ""); err == nil {
		t.Error("Render of a statement that does not encode succeeded")
	}
}

func TestRenderRawValues(t *testing.T) {
	t.Parallel()
	// Render shows what the statement says, even values the schema
	// rejects (Verify rejects them).
	st := sampleStatement()
	st.ExpiresAt = "soon"
	st.Files[0].Size = -1234
	data, sig := signed(t, st)
	doc, err := Render(st, data, sig, "en", KeysURL(hostA))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"(soon) Tj", "-1,234 bytes"} {
		if !bytes.Contains(doc, []byte(w)) {
			t.Errorf("PDF lacks %q", w)
		}
	}
	if _, err := newStatement(store.ProofDeposit, nil, store.TransferDetails{}); err == nil {
		t.Error("newStatement without tenant succeeded")
	}
}

func TestFileName(t *testing.T) {
	t.Parallel()
	if got := FileName(store.ProofDeposit, "trf_01JB0000000000000000000002"); got != "transteira-proof-deposit-trf_01JB0000000000000000000002.pdf" {
		t.Errorf("FileName = %q", got)
	}
	if got := FileName("déli/very", "trf_..\"é/x"); got != "transteira-proof-dlivery-trf_x.pdf" {
		t.Errorf("FileName(hostile) = %q", got)
	}
}

func TestVerifyRejects(t *testing.T) {
	t.Parallel()
	st := sampleStatement()
	data, sig := signed(t, st)
	keys := []PublicKey{testPub(time.Time{})}
	att := func(name string, b []byte) pdf.Attachment { return pdf.Attachment{Name: name, Data: b} }
	tamper := func(b []byte, i int) []byte { c := bytes.Clone(b); c[i] ^= 1; return c }

	// A statement signed again by another key, under the known kid.
	forged := ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32)), data)
	// A non-canonical statement (spaces), validly signed.
	spaced := append([]byte(" "), data...)
	// A statement with an extra field, canonical and signed.
	extra := []byte(strings.Replace(string(data), `{"confidentialityLevel"`, `{"comment":"x","confidentialityLevel"`, 1))
	// The same field under another case.
	cased := []byte(strings.Replace(string(data), `"senderEmail"`, `"senderemail"`, 1))
	unknownKey := st
	unknownKey.KeyID = "psk_01JB0000000000000000000009"
	ukData, ukSig := signed(t, unknownKey)

	cases := []struct {
		name string
		doc  []byte
		keys []PublicKey
		want error
	}{
		{"not a pdf", []byte("hello"), keys, ErrInvalidProof},
		{"no attachments", writePDF(t), keys, ErrInvalidProof},
		{"no signature", writePDF(t, att(StatementName, data)), keys, ErrInvalidProof},
		{"no statement", writePDF(t, att(SignatureName, sig)), keys, ErrInvalidProof},
		{"extra attachment", writePDF(t, att(StatementName, data), att(SignatureName, sig), att("x.txt", nil)), keys, ErrInvalidProof},
		{"short signature", writePDF(t, att(StatementName, data), att(SignatureName, sig[:63])), keys, ErrInvalidProof},
		{"tampered statement", writePDF(t, att(StatementName, tamper(data, bytes.IndexByte(data, '@'))), att(SignatureName, sig)), keys, ErrBadSignature},
		{"tampered signature", writePDF(t, att(StatementName, data), att(SignatureName, tamper(sig, 3))), keys, ErrBadSignature},
		{"forged signature", writePDF(t, att(StatementName, data), att(SignatureName, forged)), keys, ErrBadSignature},
		{"non canonical", writePDF(t, att(StatementName, spaced), att(SignatureName, ed25519.Sign(testKey, spaced))), keys, ErrInvalidProof},
		{"extra field", writePDF(t, att(StatementName, extra), att(SignatureName, ed25519.Sign(testKey, extra))), keys, ErrInvalidProof},
		{"field case", writePDF(t, att(StatementName, cased), att(SignatureName, ed25519.Sign(testKey, cased))), keys, ErrInvalidProof},
		{"unknown key", writePDF(t, att(StatementName, ukData), att(SignatureName, ukSig)), keys, ErrUnknownKey},
		{"no keys", writePDF(t, att(StatementName, data), att(SignatureName, sig)), nil, ErrUnknownKey},
		{"bad public key", writePDF(t, att(StatementName, data), att(SignatureName, sig)), []PublicKey{{KeyID: testKID, PublicKey: []byte{1}}}, ErrBadSignature},
		// The key was retired before the recipient's download (11:00): it
		// cannot have signed the statement.
		{
			"retired before the fact", writePDF(t, att(StatementName, data), att(SignatureName, sig)),
			[]PublicKey{testPub(testStart.Add(time.Hour))},
			ErrKeyRetired,
		},
	}
	for _, c := range cases {
		_, err := Verify(bytes.NewReader(c.doc), c.keys, DefaultVerifyLimit)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: Verify = %v, want %v", c.name, err, c.want)
		}
	}
	if _, err := Verify(bytes.NewReader(writePDF(t, att(StatementName, data), att(SignatureName, sig))), keys, 100); !errors.Is(err, ErrInvalidProof) {
		t.Errorf("Verify(over the limit) = %v", err)
	}
}

func TestParseStatement(t *testing.T) {
	t.Parallel()
	enc := func(mod func(*Statement)) []byte {
		st := sampleStatement()
		mod(&st)
		b, err := st.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	bad := map[string][]byte{
		"empty":         nil,
		"not json":      []byte("{"),
		"array":         []byte("[]"),
		"trailing":      append(enc(func(*Statement) {}), []byte("{}")...),
		"schema 2":      enc(func(s *Statement) { s.SchemaVersion = 2 }),
		"kind":          enc(func(s *Statement) { s.Kind = "receipt" }),
		"transfer id":   enc(func(s *Statement) { s.TransferID = "trf_x" }),
		"key id":        enc(func(s *Statement) { s.KeyID = "kid" }),
		"deposit dl":    enc(func(s *Statement) { s.Kind = store.ProofDeposit }),
		"deposit rdl":   enc(func(s *Statement) { s.Kind, s.FirstDownloadedAt = store.ProofDeposit, nil }),
		"delivery":      enc(func(s *Statement) { s.FirstDownloadedAt = nil }),
		"date":          enc(func(s *Statement) { s.DepositedAt = "2026-11-05T09:30:00Z" }),
		"expiry":        enc(func(s *Statement) { s.ExpiresAt = "tomorrow" }),
		"first":         enc(func(s *Statement) { d := "2026-11-05T10:00:00.000+01:00"; s.FirstDownloadedAt = &d }),
		"recipient":     enc(func(s *Statement) { s.RecipientDownloads[0].FirstDownloadedAt = "" }),
		"null files":    []byte(strings.Replace(string(enc(func(*Statement) {})), `"files":[`, `"files":null,"x":[`, 1)),
		"null level":    []byte(strings.Replace(string(enc(func(*Statement) {})), `"confidentialityLevel":"secret"`, `"confidentialityLevel":null`, 1)),
		"empty level":   []byte(strings.Replace(string(enc(func(*Statement) {})), `"confidentialityLevel":"secret"`, `"confidentialityLevel":""`, 1)),
		"float":         []byte(strings.Replace(string(enc(func(*Statement) {})), `"schemaVersion":1`, `"schemaVersion":1.5`, 1)),
		"duplicate key": []byte(strings.Replace(string(enc(func(*Statement) {})), `{"confidentialityLevel":"secret"`, `{"confidentialityLevel":"a","confidentialityLevel":"secret"`, 1)),
	}
	for name, b := range bad {
		if _, err := ParseStatement(b); !errors.Is(err, ErrInvalidProof) {
			t.Errorf("%s: ParseStatement = %v", name, err)
		}
	}
	st, err := ParseStatement(enc(func(*Statement) {}))
	if err != nil || st.FactTime() != time.Date(2026, 11, 5, 11, 0, 0, 0, time.UTC) {
		t.Errorf("ParseStatement = %+v, %v", st, err)
	}
	dep := sampleStatement()
	dep.Kind, dep.FirstDownloadedAt, dep.RecipientDownloads = store.ProofDeposit, nil, nil
	if dep.FactTime() != time.Date(2026, 11, 5, 9, 30, 0, 0, time.UTC) {
		t.Errorf("FactTime(deposit) = %v", dep.FactTime())
	}
	if got := FormatTime(time.Date(2026, 1, 2, 4, 5, 6, 789_999_999, time.FixedZone("x", 3600))); got != "2026-01-02T03:05:06.789Z" {
		t.Errorf("FormatTime = %s", got)
	}
}

// FuzzVerify feeds arbitrary documents to Verify: it never panics, and
// whatever it accepts re-encodes to its own attachment.
func FuzzVerify(f *testing.F) {
	st := sampleStatement()
	data, sig := signed(f, st)
	doc, err := Render(st, data, sig, "fr", KeysURL(hostA))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(doc)
	f.Add(writePDF(f, pdf.Attachment{Name: StatementName, Data: data}, pdf.Attachment{Name: SignatureName, Data: sig}))
	f.Add([]byte("%PDF-1.7\n"))
	keys := []PublicKey{testPub(time.Time{})}
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := Verify(bytes.NewReader(b), keys, 1<<20)
		if err != nil {
			if !errors.Is(err, ErrInvalidProof) && !errors.Is(err, ErrBadSignature) && !errors.Is(err, ErrUnknownKey) && !errors.Is(err, ErrKeyRetired) {
				t.Fatalf("unexpected error class: %v", err)
			}
			return
		}
		if _, err := got.Marshal(); err != nil {
			t.Fatalf("accepted statement does not encode: %v", err)
		}
	})
}

func TestRenderWriteFault(t *testing.T) {
	orig := pdfWrite
	t.Cleanup(func() { pdfWrite = orig })
	pdfWrite = func(io.Writer, pdf.Document) error { return errBoom }
	st := Statement{SchemaVersion: SchemaVersion, Kind: store.ProofDeposit}
	data, err := st.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Render(st, data, make([]byte, 64), "en", KeysURL(hostA)); !errors.Is(err, errBoom) {
		t.Errorf("Render(write fails) = %v", err)
	}
}
