// Package proof writes, renders and verifies the proofs of deposit and
// delivery of the transfers (CLAUDE.md section 22, threat model section
// 6.49, data model section 2.3).
//
// A proof is a statement about one fact of a transfer, signed by the
// instance:
//
//   - deposit: written when the transfer becomes available, after the
//     antivirus verdict, in the transaction that makes it available
//     ([Sealer.DepositTx]);
//   - delivery: written at the first download of the transfer
//     ([Sealer.OverallDeliveryTx]), then at the first complete download
//     of each recipient link ([Sealer.RecipientDeliveryTx]), in the
//     transaction that records it.
//
// The statement ([Statement], the OpenAPI ProofStatement) is encoded in
// canonical JSON (RFC 8785, package jcs) and signed with Ed25519 by the
// active signing key of the instance ([Signer]). Statements are immutable:
// one row per fact, never updated, kept 12 months after their creation
// even when the transfer is deleted.
//
// [Render] turns a stored proof into a PDF holding a readable copy of the
// statement and, as attached files, the signed statement itself
// (statement.json) and its signature (statement.sig): only the attached
// statement is authoritative. [Verify] checks such a PDF offline against
// the published public keys (the transteira proof verify command).
//
// [Service] serves the proofs to the sender ("my transfers") and to the
// administrators of the tenant (delegated admins, super admin, auditors).
//
// Signing keys: [Signer.Prepare] reads the active key in the system scope
// (creating it on first use) and must be called before the caller opens
// its tenant transaction: a system transaction is never opened inside a
// tenant one. [Signer.Retire] retires the active key and destroys its
// private part; its public key stays published so that the proofs it
// signed stay verifiable, and a statement whose fact postdates the
// retirement is rejected (T-300).
package proof
