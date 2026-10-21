// Package masterkey manages the master keys of an installation on top of
// internal/crypto (key format, envelope) and internal/store (tables
// wrapped_keys, master_keys and key_rotations). See
// docs/operations/master-key.md for the operator's view and the threat model
// entries T-35 to T-40, T-109 and T-116.
//
// It provides:
//
//   - [Keyring]: the current master key (TT_MASTER_KEY_FILE) and, during a
//     rotation, the new one (TT_MASTER_KEY_NEW_FILE). New wrapped keys are
//     wrapped with the new key when it is present; a wrapped key is always
//     unwrapped with the master key whose ID is stored on its row. [Keyring.MAC]
//     and [Keyring.VerifyMAC] key the verification code hashes, the CSRF
//     tokens, the recognition cookie entries and the download grant cookie
//     entries with the current key only, so finishing a rotation
//     invalidates the outstanding ones.
//   - [Vault]: the tenant-scoped operations the rest of the application uses:
//     [Vault.Seal] wraps and stores a secret or a data encryption key,
//     [Vault.Open] reads it back, [Vault.Destroy] crypto-erases it and
//     scrubs the database files; [Vault.SealTx], [Vault.NewDEKTx] and
//     [Vault.DestroyTx] do the same inside the caller's transaction.
//   - [Check]: the startup check, which refuses to start when the database
//     needs a master key that is not provided, when a completed rotation was
//     not followed by the switch of TT_MASTER_KEY_FILE, when the new key is
//     retired, or when a running rotation does not match the new key.
//   - [StartRotation] and [Rotate]: the resumable rotation, which re-wraps
//     every row of wrapped_keys from the current key to the new key in short
//     batches; [Recover] re-wraps rows left under a retired key (clean-up
//     rotation) and [Abandon] gives up a clean-up rotation, or a regular
//     rotation nothing depends on yet.
//
// Error messages and logs identify master keys only by their public ID
// ("mk_" and 16 hexadecimal characters); key bytes and unwrapped secrets are
// never logged nor included in an error.
//
// # Sources of wrapped keys
//
// Today wrapped_keys is the only table holding wrapped keys: transfer files
// and tenant settings (SMTP password) refer to its rows by ID, so the
// rotation has a single source to walk. Secrets that are not attached to a
// tenant (the TOTP secrets of administrators, added by the administration
// step) will be a second source. Such a source plugs in by providing the
// same three operations the store offers for wrapped_keys: the master key
// IDs it uses (read by [Check] alongside KeyIDsInUse), the number of rows
// still under a key (for the rotation total and for the completion check),
// and a batched re-wrap that calls back for each row. The rotation then
// drains each source in turn before completing, with the same
// unwrap-and-wrap callback bound to the source's own purpose and row
// identifiers. Such secrets have no tenant: they must be bound to a fixed
// sentinel tenant identifier (for example "system"), never to an empty
// string, which the envelope refuses and which would blur the binding.
package masterkey
