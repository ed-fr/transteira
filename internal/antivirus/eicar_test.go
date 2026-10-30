package antivirus

import (
	"bytes"
	"os"
	"testing"

	"github.com/ed-fr/transteira/internal/antivirus/antivirustest"
)

func TestEICAR(t *testing.T) {
	got := EICAR()
	if len(got) != 68 || !bytes.Equal(got, antivirustest.EICAR()) {
		t.Fatalf("EICAR() = %q", got)
	}
	// Every call returns its own copy.
	got[0] = 0
	if EICAR()[0] == 0 {
		t.Fatal("EICAR() shares its buffer")
	}
}

func TestEICARNotInSource(t *testing.T) {
	src, err := os.ReadFile("eicar.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range [][]byte{antivirustest.EICAR(), []byte("EICAR-STANDARD"), []byte("ANTIVIRUS-TEST-FILE")} {
		if bytes.Contains(src, needle) {
			t.Fatalf("eicar.go contains %q in clear", needle)
		}
	}
}
