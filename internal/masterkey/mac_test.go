package masterkey_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ed-fr/transteira/internal/crypto"
	"github.com/ed-fr/transteira/internal/masterkey"
	"github.com/ed-fr/transteira/internal/masterkey/masterkeytest"
)

func TestKeyringMAC(t *testing.T) {
	t.Parallel()
	cur, next := newKey(t), newKey(t)
	code := [][]byte{[]byte("vch_1"), []byte("123456")}

	// The keyring MACs with the current key, with or without a new key.
	alone := keyring(t, cur, nil)
	mac, err := alone.MAC(crypto.MACPurposeOTP, code...)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := cur.MAC(crypto.MACPurposeOTP, code...)
	if err != nil || !bytes.Equal(mac, direct) {
		t.Fatalf("keyring MAC is not the current key's: %v", err)
	}
	rotating := keyring(t, cur, next)
	if m, err := rotating.MAC(crypto.MACPurposeOTP, code...); err != nil || !bytes.Equal(m, mac) {
		t.Fatalf("MAC during a rotation = %x, %v; want the current key's", m, err)
	}
	if ok, err := rotating.VerifyMAC(crypto.MACPurposeOTP, mac, code...); !ok || err != nil {
		t.Fatalf("VerifyMAC during a rotation = %v, %v", ok, err)
	}
	if ok, err := alone.VerifyMAC(crypto.MACPurposeCSRF, mac, code...); ok || err != nil {
		t.Errorf("VerifyMAC(other purpose) = %v, %v", ok, err)
	}
	if _, err := alone.MAC("unknown", code...); !errors.Is(err, crypto.ErrUnknownMACPurpose) {
		t.Errorf("MAC(unknown purpose) = %v", err)
	}
	if ok, err := alone.VerifyMAC("unknown", mac, code...); ok || !errors.Is(err, crypto.ErrUnknownMACPurpose) {
		t.Errorf("VerifyMAC(unknown purpose) = %v, %v", ok, err)
	}

	// After the rotation, TT_MASTER_KEY_FILE names the new key: outstanding
	// MACs no longer verify, new ones do.
	switched := keyring(t, next, nil)
	if ok, err := switched.VerifyMAC(crypto.MACPurposeOTP, mac, code...); ok || err != nil {
		t.Fatalf("old MAC after the switch = %v, %v; want invalid", ok, err)
	}
	fresh, err := switched.MAC(crypto.MACPurposeOTP, code...)
	if err != nil || bytes.Equal(fresh, mac) {
		t.Fatalf("MAC after the switch = %x, %v", fresh, err)
	}
	if ok, err := switched.VerifyMAC(crypto.MACPurposeOTP, fresh, code...); !ok || err != nil {
		t.Fatalf("new MAC after the switch = %v, %v", ok, err)
	}
}

func TestKeyringMACAfterClose(t *testing.T) {
	t.Parallel()
	kr, err := masterkey.New(masterkeytest.Key(t, "mac close current"), masterkeytest.Key(t, "mac close new"))
	if err != nil {
		t.Fatal(err)
	}
	mac, err := kr.MAC(crypto.MACPurposeCSRF, []byte("ds_token"))
	if err != nil {
		t.Fatal(err)
	}
	kr.Close()
	if _, err := kr.MAC(crypto.MACPurposeCSRF, []byte("ds_token")); !errors.Is(err, crypto.ErrKeyUnavailable) {
		t.Errorf("MAC after Close = %v", err)
	}
	if ok, err := kr.VerifyMAC(crypto.MACPurposeCSRF, mac, []byte("ds_token")); ok || !errors.Is(err, crypto.ErrKeyUnavailable) {
		t.Errorf("VerifyMAC after Close = %v, %v", ok, err)
	}
}
