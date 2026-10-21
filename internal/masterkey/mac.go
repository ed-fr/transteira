package masterkey

import "github.com/ed-fr/transteira/internal/crypto"

// MAC returns the keyed MAC of parts for purpose p (see crypto.MasterKey.MAC)
// under the CURRENT master key (TT_MASTER_KEY_FILE), never the new one.
//
// These MACs protect values that can be lost without harm: the hashes of
// the one-time verification codes (valid 15 minutes), the CSRF tokens of
// deposit sessions (4 hours), the entries of the browser recognition
// cookie of verified depositors (12 months) and the entries of the download
// grant cookie set once a transfer password has been entered (1 hour). They
// are not re-keyed by a rotation. While a rotation runs,
// TT_MASTER_KEY_FILE does not change, so they stay valid; once the rotation
// is finished and TT_MASTER_KEY_FILE switches to the new key, the
// outstanding codes and CSRF tokens no longer verify (users request a new
// code or reload the page), every recognition cookie is ignored (each
// depositor enters a code once more, which sets a new cookie) and every
// download grant is ignored (recipients enter the transfer password once
// more). It fails with crypto.ErrKeyUnavailable after Close.
func (k *Keyring) MAC(p crypto.MACPurpose, parts ...[]byte) ([]byte, error) {
	return k.current.MAC(p, parts...)
}

// VerifyMAC reports, in constant time, whether mac is the MAC of parts for
// purpose p under the current master key (see MAC for the effect of a
// rotation).
func (k *Keyring) VerifyMAC(p crypto.MACPurpose, mac []byte, parts ...[]byte) (bool, error) {
	return k.current.VerifyMAC(p, mac, parts...)
}
