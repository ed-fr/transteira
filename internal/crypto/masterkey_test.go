package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testKeyID is the frozen identifier of the fixed test key. Changing the key
// identifier derivation breaks every stored key reference: this value must
// never change.
const testKeyID = "mk_9253a0819ebb77c6"

func TestParseMasterKeyValid(t *testing.T) {
	for name, in := range map[string]string{
		"plain":           testKeyB64,
		"trailing LF":     testKeyB64 + "\n",
		"trailing CRLF":   testKeyB64 + "\r\n",
		"surrounding":     " \t\n" + testKeyB64 + " \r\n\t",
		"leading newline": "\n" + testKeyB64,
	} {
		t.Run(name, func(t *testing.T) {
			k, err := ParseMasterKey([]byte(in))
			if err != nil {
				t.Fatalf("ParseMasterKey: %v", err)
			}
			if k.ID() != testKeyID {
				t.Fatalf("ID = %q, want %q", k.ID(), testKeyID)
			}
			if !bytes.Equal(k.m.key[:], pattern32()) {
				t.Fatal("key bytes not decoded as expected")
			}
		})
	}
}

// pattern32 returns bytes 0x00..0x1f, the decoded test key.
func pattern32() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestParseMasterKeyInvalid(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, 31))
	long := base64.StdEncoding.EncodeToString(make([]byte, 33))
	cases := map[string]string{
		"empty":            "",
		"whitespace":       " \n ",
		"31 bytes":         short,
		"33 bytes":         long,
		"one char less":    testKeyB64[:43],
		"one char more":    testKeyB64 + "A",
		"no padding":       strings.TrimRight(testKeyB64, "=") + "A",
		"double padding":   testKeyB64[:42] + "==",
		"url alphabet":     "-" + testKeyB64[1:],
		"invalid char":     "*" + testKeyB64[1:],
		"non canonical":    testKeyB64[:42] + "9=",
		"inner newline":    testKeyB64[:20] + "\n" + testKeyB64[21:],
		"inner space":      testKeyB64[:20] + " " + testKeyB64[21:],
		"hex instead":      hex.EncodeToString(pattern32()),
		"raw 32 bytes":     string(pattern32()),
		"two keys":         testKeyB64 + "\n" + testKeyB64,
		"quoted":           `"` + testKeyB64[:42] + `"`,
		"key with comment": testKeyB64 + " # comment",
		"UTF-8 BOM":        "\xEF\xBB\xBF" + testKeyB64,
		"UTF-8 BOM + LF":   "\xEF\xBB\xBF" + testKeyB64 + "\n",
		"UTF-16 BOM":       "\xFF\xFE" + testKeyB64,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			k, err := ParseMasterKey([]byte(in))
			if !errors.Is(err, ErrInvalidMasterKey) || k != nil {
				t.Fatalf("ParseMasterKey = %v, %v; want ErrInvalidMasterKey", k, err)
			}
			if strings.TrimSpace(in) != "" && strings.Contains(err.Error(), strings.TrimSpace(in)) {
				t.Fatal("error echoes the input")
			}
		})
	}
}

func TestMasterKeyIDDistinct(t *testing.T) {
	a, b := testKey(t), otherKey(t)
	if a.ID() == b.ID() {
		t.Fatal("two keys share an ID")
	}
	if len(a.ID()) != 3+16 || !strings.HasPrefix(a.ID(), "mk_") {
		t.Fatalf("ID format: %q", a.ID())
	}
	if (*MasterKey)(nil).ID() != "" || (&MasterKey{}).ID() != "" {
		t.Fatal("nil key must have an empty ID")
	}
}

func TestLoadMasterKey(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	k, err := LoadMasterKey(write("ok.key", []byte(testKeyB64+"\n")))
	if err != nil || k.ID() != testKeyID {
		t.Fatalf("LoadMasterKey = %v, %v", k, err)
	}

	big := append([]byte(testKeyB64), bytes.Repeat([]byte(" "), 2000)...)
	if _, err := LoadMasterKey(write("big.key", big)); !errors.Is(err, ErrInvalidMasterKey) {
		t.Fatalf("big file: %v", err)
	}
	exact := append([]byte(testKeyB64), bytes.Repeat([]byte("\n"), maxMasterKeyFileSize-len(testKeyB64))...)
	if _, err := LoadMasterKey(write("exact.key", exact)); err != nil {
		t.Fatalf("1 KiB file: %v", err)
	}
	if _, err := LoadMasterKey(write("bad.key", []byte("not a key"))); !errors.Is(err, ErrInvalidMasterKey) {
		t.Fatalf("bad file: %v", err)
	}
	if _, err := LoadMasterKey(filepath.Join(dir, "missing.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	if _, err := LoadMasterKey(dir); err == nil || errors.Is(err, ErrInvalidMasterKey) {
		t.Fatalf("directory: %v", err)
	}
}

// secretForms returns textual forms of the test key bytes that must never
// appear in any output.
func secretForms() []string {
	raw := pattern32()
	return []string{
		testKeyB64,
		testKeyB64[:20],
		hex.EncodeToString(raw),
		hex.EncodeToString(raw)[:20],
		fmt.Sprintf("%v", raw),
		fmt.Sprintf("%v", raw[1:9]),
		string(raw[8:24]),
	}
}

func assertRedacted(t *testing.T, label, out string) {
	t.Helper()
	for _, s := range secretForms() {
		if strings.Contains(out, s) {
			t.Fatalf("%s leaks key material: %q", label, out)
		}
	}
}

func TestMasterKeyRedaction(t *testing.T) {
	k := testKey(t)
	want := "MasterKey(" + testKeyID + ")"
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T: %[1]v", "%10.3v"} {
		for _, v := range []any{k, *k} {
			out := fmt.Sprintf(verb, v)
			assertRedacted(t, verb, out)
			if !strings.Contains(out, want) {
				t.Fatalf("%s = %q, want it to contain %q", verb, out, want)
			}
		}
	}
	// Inside other values.
	wrapped := struct {
		Key  *MasterKey
		Keys []MasterKey
		Map  map[string]*MasterKey
	}{k, []MasterKey{*k}, map[string]*MasterKey{"a": k}}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		assertRedacted(t, "nested "+verb, fmt.Sprintf(verb, wrapped))
	}
	if got := k.String(); got != want {
		t.Fatalf("String = %q", got)
	}
	if got := k.GoString(); got != want {
		t.Fatalf("GoString = %q", got)
	}
	if got := (MasterKey{}).String(); got != "MasterKey(none)" {
		t.Fatalf("zero String = %q", got)
	}
	if got := fmt.Sprint((*MasterKey)(nil)); got != "<nil>" {
		t.Fatalf("nil Sprint = %q", got)
	}

	// slog, JSON and text.
	var buf bytes.Buffer
	for _, h := range []slog.Handler{slog.NewJSONHandler(&buf, nil), slog.NewTextHandler(&buf, nil)} {
		l := slog.New(h)
		l.Info("loaded", "key", k, "value", *k, slog.Any("any", k), slog.Group("g", "key", k))
		l.Info("nested", "s", wrapped)
	}
	assertRedacted(t, "slog", buf.String())
	if strings.Count(buf.String(), want) < 8 {
		t.Fatalf("slog output lacks the redacted form: %s", buf.String())
	}
	if got := k.LogValue().String(); got != want {
		t.Fatalf("LogValue = %q", got)
	}

	// encoding/json sees no exported field.
	j, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	assertRedacted(t, "json", string(j))

	// Errors never carry the key.
	_, err = ParseMasterKey([]byte(testKeyB64[:43]))
	assertRedacted(t, "error", err.Error())
}

func TestMasterKeyDestroy(t *testing.T) {
	k := testKey(t)
	blob, err := k.Wrap(PurposeDEK, "ten_a", "wk_a", testDEK(1))
	if err != nil {
		t.Fatal(err)
	}
	id := k.ID()
	k.Destroy()
	if !bytes.Equal(k.m.key[:], make([]byte, MasterKeySize)) {
		t.Fatal("key bytes not zeroed")
	}
	if k.ID() != id {
		t.Fatal("ID changed after Destroy")
	}
	if _, err := k.Wrap(PurposeDEK, "ten_a", "wk_a", testDEK(1)); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("Wrap after Destroy: %v", err)
	}
	_, err = k.Unwrap(PurposeDEK, "ten_a", "wk_a", blob)
	if !errors.Is(err, ErrUnwrap) || !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("Unwrap after Destroy: %v", err)
	}
	k.Destroy() // idempotent
	(*MasterKey)(nil).Destroy()
	(&MasterKey{}).Destroy()
}

func TestParseMasterKeyDegenerate(t *testing.T) {
	for _, b := range []byte{0x00, 0x01, 0x41, 0xFF} {
		in := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, MasterKeySize))
		if _, err := ParseMasterKey([]byte(in)); !errors.Is(err, ErrInvalidMasterKey) {
			t.Fatalf("repeated 0x%02x: %v", b, err)
		}
	}
	almost := bytes.Repeat([]byte{0}, MasterKeySize)
	almost[31] = 1
	if _, err := ParseMasterKey([]byte(base64.StdEncoding.EncodeToString(almost))); err != nil {
		t.Fatalf("two distinct bytes refused: %v", err)
	}
	if _, err := ParseMasterKey([]byte(testKeyB64)); err != nil {
		t.Fatalf("test key refused: %v", err)
	}
}
