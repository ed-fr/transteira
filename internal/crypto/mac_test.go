package crypto

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
)

func TestMAC(t *testing.T) {
	t.Parallel()
	k := testKey(t)
	a, err := k.MAC(MACPurposeOTP, []byte("vch_1"), []byte("123456"))
	if err != nil || len(a) != MACSize {
		t.Fatalf("MAC = %x, %v", a, err)
	}
	again, err := k.MAC(MACPurposeOTP, []byte("vch_1"), []byte("123456"))
	if err != nil || !bytes.Equal(a, again) {
		t.Fatal("MAC is not deterministic")
	}

	// Every change of purpose, key, part or part boundary changes the MAC.
	distinct := map[string][]byte{"base": a}
	add := func(name string, mac []byte, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for other, m := range distinct {
			if bytes.Equal(m, mac) {
				t.Fatalf("%s collides with %s", name, other)
			}
		}
		distinct[name] = mac
	}
	m, err := k.MAC(MACPurposeCSRF, []byte("vch_1"), []byte("123456"))
	add("csrf purpose", m, err)
	m, err = otherKey(t).MAC(MACPurposeOTP, []byte("vch_1"), []byte("123456"))
	add("other key", m, err)
	m, err = k.MAC(MACPurposeOTP, []byte("vch_1"), []byte("123457"))
	add("other code", m, err)
	m, err = k.MAC(MACPurposeOTP, []byte("vch_11"), []byte("23456"))
	add("shifted boundary", m, err)
	m, err = k.MAC(MACPurposeOTP, []byte("vch_1123456"))
	add("single part", m, err)
	m, err = k.MAC(MACPurposeOTP, []byte("vch_1"), []byte("123456"), nil)
	add("extra empty part", m, err)
	m, err = k.MAC(MACPurposeOTP)
	add("no part", m, err)
	m, err = k.MAC(MACPurposeOTP, nil)
	add("one empty part", m, err)
}

func TestMACKeysSeparated(t *testing.T) {
	t.Parallel()
	k := testKey(t)
	// The MAC keys are the documented HKDF outputs, distinct from each other
	// and from the wrapping keys (whose info strings use another prefix).
	seen := map[string]string{}
	for _, p := range macPurposes {
		want, err := hkdf.Key(sha256.New, k.m.key[:], nil, "transteira/v1/mac/"+string(p), MasterKeySize)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(k.m.mac[p], want) {
			t.Fatalf("MAC key of %s is not the documented derivation", p)
		}
		seen[string(want)] = "mac/" + string(p)
	}
	for _, p := range purposes {
		wk, err := hkdf.Key(sha256.New, k.m.key[:], nil, wrapInfoPrefix+string(p), MasterKeySize)
		if err != nil {
			t.Fatal(err)
		}
		if other, dup := seen[string(wk)]; dup {
			t.Fatalf("wrap key of %s equals %s", p, other)
		}
		seen[string(wk)] = "wrap/" + string(p)
	}
	if len(seen) != len(macPurposes)+len(purposes) {
		t.Fatal("derived keys collide")
	}
}

func TestMACErrors(t *testing.T) {
	t.Parallel()
	k := testKey(t)
	for _, p := range []MACPurpose{"", "OTP", "dek", "secret", "otp "} {
		if _, err := k.MAC(p, []byte("x")); !errors.Is(err, ErrUnknownMACPurpose) {
			t.Errorf("MAC(%q) = %v", p, err)
		}
		if ok, err := k.VerifyMAC(p, make([]byte, MACSize), []byte("x")); ok || !errors.Is(err, ErrUnknownMACPurpose) {
			t.Errorf("VerifyMAC(%q) = %v, %v", p, ok, err)
		}
	}

	limit := make([]byte, MaxMACPartSize)
	if _, err := k.MAC(MACPurposeCSRF, []byte("a"), limit); err != nil {
		t.Errorf("MAC(part of MaxMACPartSize) = %v", err)
	}
	big := make([]byte, MaxMACPartSize+1)
	if _, err := k.MAC(MACPurposeCSRF, []byte("a"), big); !errors.Is(err, ErrMACPartTooLarge) {
		t.Errorf("MAC(oversized part) = %v", err)
	}
	if ok, err := k.VerifyMAC(MACPurposeCSRF, make([]byte, MACSize), big); ok || !errors.Is(err, ErrMACPartTooLarge) {
		t.Errorf("VerifyMAC(oversized part) = %v, %v", ok, err)
	}

	for name, nk := range map[string]*MasterKey{"nil": nil, "zero": {}} {
		if _, err := nk.MAC(MACPurposeOTP); !errors.Is(err, ErrKeyUnavailable) {
			t.Errorf("MAC on %s key = %v", name, err)
		}
		if ok, err := nk.VerifyMAC(MACPurposeOTP, nil); ok || !errors.Is(err, ErrKeyUnavailable) {
			t.Errorf("VerifyMAC on %s key = %v, %v", name, ok, err)
		}
	}
}

func TestVerifyMAC(t *testing.T) {
	t.Parallel()
	k := testKey(t)
	parts := [][]byte{[]byte("ds_token")}
	mac, err := k.MAC(MACPurposeCSRF, parts...)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := k.VerifyMAC(MACPurposeCSRF, mac, parts...); !ok || err != nil {
		t.Fatalf("VerifyMAC(valid) = %v, %v", ok, err)
	}
	flipped := bytes.Clone(mac)
	flipped[MACSize-1] ^= 1
	for name, bad := range map[string][]byte{
		"flipped": flipped, "truncated": mac[:MACSize-1], "extended": append(bytes.Clone(mac), 0),
		"empty": nil, "zero": make([]byte, MACSize),
	} {
		if ok, err := k.VerifyMAC(MACPurposeCSRF, bad, parts...); ok || err != nil {
			t.Errorf("VerifyMAC(%s) = %v, %v", name, ok, err)
		}
	}
	if ok, err := k.VerifyMAC(MACPurposeOTP, mac, parts...); ok || err != nil {
		t.Errorf("VerifyMAC(other purpose) = %v, %v", ok, err)
	}
	if ok, err := otherKey(t).VerifyMAC(MACPurposeCSRF, mac, parts...); ok || err != nil {
		t.Errorf("VerifyMAC(other key) = %v, %v", ok, err)
	}
	if ok, err := k.VerifyMAC(MACPurposeCSRF, mac, []byte("ds_other")); ok || err != nil {
		t.Errorf("VerifyMAC(other part) = %v, %v", ok, err)
	}
}

func TestMACDestroy(t *testing.T) {
	t.Parallel()
	k := testKey(t)
	mac, err := k.MAC(MACPurposeOTP, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	keys := make([][]byte, 0, len(macPurposes))
	for _, p := range macPurposes {
		keys = append(keys, k.m.mac[p])
	}
	k.Destroy()
	for i, mk := range keys {
		if !bytes.Equal(mk, make([]byte, MasterKeySize)) {
			t.Errorf("MAC key %s not zeroed", macPurposes[i])
		}
	}
	if k.m.mac != nil {
		t.Error("MAC keys not dropped")
	}
	if _, err := k.MAC(MACPurposeOTP, []byte("x")); !errors.Is(err, ErrKeyUnavailable) {
		t.Errorf("MAC after Destroy = %v", err)
	}
	if ok, err := k.VerifyMAC(MACPurposeOTP, mac, []byte("x")); ok || !errors.Is(err, ErrKeyUnavailable) {
		t.Errorf("VerifyMAC after Destroy = %v, %v", ok, err)
	}
}

func TestMACConcurrent(t *testing.T) {
	t.Parallel()
	k := testKey(t)
	want, err := k.MAC(MACPurposeCSRF, []byte("token"))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				if ok, err := k.VerifyMAC(MACPurposeCSRF, want, []byte("token")); !ok || err != nil {
					t.Errorf("concurrent VerifyMAC = %v, %v", ok, err)
					return
				}
			}
		})
	}
	wg.Wait()
}
