// Package masterkey manages the master keys of an installation on top of
// internal/crypto (key format, envelope) and internal/store (tables
// wrapped_keys, system_secrets, master_keys and key_rotations). See
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
//     [Vault.WrapSystem] and [Vault.OpenSystem] do the same for the system
//     secrets, which belong to no tenant (the administrator TOTP secrets).
//   - [Check]: the startup check, which refuses to start when the database
//     needs a master key that is not provided, when a completed rotation was
//     not followed by the switch of TT_MASTER_KEY_FILE, when the new key is
//     retired, or when a running rotation does not match the new key.
//   - [StartRotation] and [Rotate]: the resumable rotation, which re-wraps
//     every row of wrapped_keys and of system_secrets from the current key
//     to the new key in short batches; [Recover] re-wraps rows left under a retired key (clean-up
//     rotation) and [Abandon] gives up a clean-up rotation, or a regular
//     rotation nothing depends on yet.
//
// Error messages and logs identify master keys only by their public ID
// ("mk_" and 16 hexadecimal characters); key bytes and unwrapped secrets are
// never logged nor included in an error.
//
// # Sources of wrapped keys
//
// Two tables hold wrapped blobs:
//
//   - wrapped_keys: the data encryption keys of the files and the secrets
//     of the tenant settings (SMTP password), referenced by ID. A row is
//     bound to its tenant and its "wk_" ID: the envelope AAD carries
//     lp(purpose) | lp(tenant ID) | lp(row ID).
//   - system_secrets: the secrets that belong to no tenant: the TOTP
//     secrets of the administrators (crypto.PurposeAdminTOTP) and the URL
//     and signing secret of the instance-wide webhooks
//     (crypto.PurposeWebhook). A row is
//     bound to the reserved tenant binding "system" and to its own "ss_" ID,
//     the exact counterpart of a tenant key. A tenant ID is always "ten_"
//     followed by a ULID, so it never equals "system", and the row prefixes
//     differ: a system secret never unwraps as a tenant key nor under
//     another row, and conversely. The binding is never empty, which the
//     envelope refuses.
//
// The store covers both tables in the master key operations: KeyIDsInUse
// (read by [Check]) and CountByKey (the rotation total and the completion
// check) include system_secrets, so a rotation cannot complete, nor a
// regular one be abandoned, while a system secret depends on its keys.
// [Rotate] and [Recover] drain wrapped_keys then system_secrets, in batches
// of short transactions (RewrapBatch then RewrapSystemSecretsBatch), with
// the same unwrap-and-wrap step bound to each source's binding, before
// completing.
package masterkey
