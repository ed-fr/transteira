package proof

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/jcs"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/version"
)

// golden replaces the variable parts of a golden statement.
func golden(s, trfID, kid string) string {
	return strings.NewReplacer("{trf}", trfID, "{kid}", kid, "{version}", version.Get().Version).Replace(s)
}

// Golden statements (canonical JSON, RFC 8785: keys sorted, no space).
// The first seeded transfer is finalized at 09:30 and available at 09:31,
// for 7 days.
const (
	goldenFiles = `"files":[{"name":"plans.pdf","scanStatus":"clean","sha256":"` + sumA + `","size":1000},` +
		`{"name":"vidéo (1).mp4","path":"docs/2026","scanStatus":"not_scanned_too_large","sha256":"` + sumB + `","size":3000000000}]`
	goldenDeposit = `{"confidentialityLevel":"secret","depositedAt":"2026-11-05T09:30:00.000Z","endToEndEncrypted":false,` +
		`"expiresAt":"2026-11-12T09:31:00.000Z",` + goldenFiles + `,"firstDownloadedAt":null,"instanceVersion":"{version}",` +
		`"keyId":"{kid}","kind":"deposit","recipients":["` + carol + `","` + dave + `"],"schemaVersion":1,` +
		`"senderEmail":"` + aliceNorm + `","tenant":{"fqdn":"` + hostA + `","name":"Entity A"},"transferId":"{trf}"}`
	goldenSharedDelivery = `{"depositedAt":"2026-11-05T09:31:00.000Z","endToEndEncrypted":false,` +
		`"expiresAt":"2026-11-12T09:32:00.000Z",` + goldenFiles + `,"firstDownloadedAt":"2026-11-05T10:00:00.000Z",` +
		`"instanceVersion":"{version}","keyId":"{kid}","kind":"delivery","recipients":["` + carol + `","` + dave + `"],` +
		`"schemaVersion":1,"senderEmail":"` + aliceNorm + `","tenant":{"fqdn":"` + hostA + `","name":"Entity A"},"transferId":"{trf}"}`
)

// checkSigned checks that p holds the canonical statement want, signed by
// the active key, kept 12 months.
func checkSigned(t *testing.T, ev *env, p store.TransferProof, want string) {
	t.Helper()
	if string(p.Statement) != want {
		t.Errorf("statement =\n%s\nwant\n%s", p.Statement, want)
	}
	if c, err := jcs.Canonicalize(p.Statement); err != nil || string(c) != string(p.Statement) {
		t.Errorf("statement not canonical: %v", err)
	}
	keys := ev.keys()
	if _, err := VerifyStatement(p.Statement, p.Signature, keys); err != nil {
		t.Errorf("VerifyStatement = %v", err)
	}
	if !p.ExpiresAt.Equal(p.CreatedAt.AddDate(1, 0, 0)) {
		t.Errorf("expires %v, created %v", p.ExpiresAt, p.CreatedAt)
	}
}

func TestDepositAndSharedDelivery(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		trf := ev.seed(ev.a, seedOptions{level: true})
		dep := ev.proofRow(ev.a, trf.id, store.ProofDeposit, "")
		kid := ev.keys()[0].KeyID
		checkSigned(t, ev, dep, golden(goldenDeposit, trf.id, kid))
		if !dep.CreatedAt.Equal(testStart.Add(time.Minute)) || dep.KeyID != kid {
			t.Errorf("deposit row = %+v", dep)
		}
		if _, err := ev.db.TransferProofs().Get(t.Context(), ev.a.ID, trf.id, store.ProofDelivery, ""); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("delivery before download = %v", err)
		}

		// A shared transfer gets one delivery proof, at its first download.
		plain := ev.seed(ev.a, seedOptions{}) // finalized 09:31, available 09:32
		ev.clock.Advance(28 * time.Minute)    // 10:00
		ev.download(ev.a, plain.id, "")
		ev.clock.Advance(time.Hour)
		ev.download(ev.a, plain.id, "")
		del := ev.proofRow(ev.a, plain.id, store.ProofDelivery, "")
		checkSigned(t, ev, del, golden(goldenSharedDelivery, plain.id, kid))
		if !del.CreatedAt.Equal(testStart.Add(30 * time.Minute)) {
			t.Errorf("delivery created %v", del.CreatedAt)
		}
	})
}

func TestPerRecipientDelivery(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		trf := ev.seed(ev.a, seedOptions{perRecipient: true})
		if len(trf.links) != 2 || trf.links[0].Email != carol || trf.links[1].Email != dave {
			t.Fatalf("links = %+v", trf.links)
		}
		kid := ev.keys()[0].KeyID
		ev.clock.Advance(29 * time.Minute) // 10:00: carol
		ev.download(ev.a, trf.id, trf.links[0].ID)
		ev.clock.Advance(time.Hour) // 11:00: dave, then carol again
		ev.download(ev.a, trf.id, trf.links[1].ID)
		ev.download(ev.a, trf.id, trf.links[0].ID)

		base := `{"depositedAt":"2026-11-05T09:30:00.000Z","endToEndEncrypted":false,` +
			`"expiresAt":"2026-11-12T09:31:00.000Z",` + goldenFiles + `,"firstDownloadedAt":"2026-11-05T10:00:00.000Z",` +
			`"instanceVersion":"{version}","keyId":"{kid}","kind":"delivery","recipientDownloads":[%s],` +
			`"recipients":["` + carol + `","` + dave + `"],"schemaVersion":1,"senderEmail":"` + aliceNorm + `",` +
			`"tenant":{"fqdn":"` + hostA + `","name":"Entity A"},"transferId":"{trf}"}`
		carolDL := `{"email":"` + carol + `","firstDownloadedAt":"2026-11-05T10:00:00.000Z"}`
		daveDL := `{"email":"` + dave + `","firstDownloadedAt":"2026-11-05T11:00:00.000Z"}`
		with := func(dl string) string { return golden(strings.Replace(base, "%s", dl, 1), trf.id, kid) }

		// The overall proof is written with carol's: she is the only one
		// who downloaded then.
		checkSigned(t, ev, ev.proofRow(ev.a, trf.id, store.ProofDelivery, ""), with(carolDL))
		checkSigned(t, ev, ev.proofRow(ev.a, trf.id, store.ProofDelivery, trf.links[0].ID), with(carolDL))
		dp := ev.proofRow(ev.a, trf.id, store.ProofDelivery, trf.links[1].ID)
		checkSigned(t, ev, dp, with(daveDL))
		if !dp.CreatedAt.Equal(testStart.Add(90 * time.Minute)) {
			t.Errorf("dave's proof created %v", dp.CreatedAt)
		}

		// Overall proof written once both completed: both are named.
		both := ev.seed(ev.a, seedOptions{perRecipient: true})
		sealer := ev.prepare()
		err := ev.tx(ev.a, func(tx *store.ScopedTx) error {
			now := ev.clock.Now()
			for _, l := range both.links {
				if err := ev.db.RecipientLinks().ClaimTx(t.Context(), tx, l.ID, "", now); err != nil {
					return err
				}
				if _, err := ev.db.RecipientLinks().CompleteTx(t.Context(), tx, l.ID, now); err != nil {
					return err
				}
			}
			if _, err := ev.db.Transfers().MarkFirstDownloadTx(t.Context(), tx, both.id, now, time.Time{}); err != nil {
				return err
			}
			return sealer.OverallDeliveryTx(t.Context(), tx, ev.a, both.id, now)
		})
		if err != nil {
			t.Fatal(err)
		}
		st, err := ParseStatement(ev.proofRow(ev.a, both.id, store.ProofDelivery, "").Statement)
		if err != nil || len(st.RecipientDownloads) != 2 || st.RecipientDownloads[0].Email != carol || st.RecipientDownloads[1].Email != dave {
			t.Errorf("overall statement = %+v, %v", st, err)
		}
	})
}

func TestSealIdempotentAndNotReady(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := t.Context()
		trf := ev.seed(ev.a, seedOptions{perRecipient: true})
		ev.download(ev.a, trf.id, trf.links[0].ID)
		before := map[string]store.TransferProof{
			"deposit": ev.proofRow(ev.a, trf.id, store.ProofDeposit, ""),
			"overall": ev.proofRow(ev.a, trf.id, store.ProofDelivery, ""),
			"carol":   ev.proofRow(ev.a, trf.id, store.ProofDelivery, trf.links[0].ID),
		}
		// A retried write keeps the proof of the fact (immutable).
		ev.clock.Advance(time.Hour)
		sealer := ev.prepare()
		err := ev.tx(ev.a, func(tx *store.ScopedTx) error {
			now := ev.clock.Now()
			return errors.Join(
				sealer.DepositTx(ctx, tx, ev.a, trf.id, now),
				sealer.OverallDeliveryTx(ctx, tx, ev.a, trf.id, now),
				sealer.RecipientDeliveryTx(ctx, tx, ev.a, trf.id, trf.links[0].ID, now))
		})
		if err != nil {
			t.Fatalf("retried writes = %v", err)
		}
		after := map[string]store.TransferProof{
			"deposit": ev.proofRow(ev.a, trf.id, store.ProofDeposit, ""),
			"overall": ev.proofRow(ev.a, trf.id, store.ProofDelivery, ""),
			"carol":   ev.proofRow(ev.a, trf.id, store.ProofDelivery, trf.links[0].ID),
		}
		for k, p := range before {
			if after[k].ID != p.ID || string(after[k].Statement) != string(p.Statement) {
				t.Errorf("%s proof changed", k)
			}
		}

		// Facts that are not recorded.
		scanning := ev.seed(ev.a, seedOptions{scanning: true})
		fresh := ev.seed(ev.a, seedOptions{perRecipient: true})
		for name, fn := range map[string]func(tx *store.ScopedTx) error{
			"deposit of a scanning transfer": func(tx *store.ScopedTx) error {
				return sealer.DepositTx(ctx, tx, ev.a, scanning.id, ev.clock.Now())
			},
			"delivery without download": func(tx *store.ScopedTx) error {
				return sealer.OverallDeliveryTx(ctx, tx, ev.a, fresh.id, ev.clock.Now())
			},
			"recipient delivery without download": func(tx *store.ScopedTx) error {
				return sealer.RecipientDeliveryTx(ctx, tx, ev.a, fresh.id, fresh.links[0].ID, ev.clock.Now())
			},
			"recipient delivery of another transfer's link": func(tx *store.ScopedTx) error {
				return sealer.RecipientDeliveryTx(ctx, tx, ev.a, trf.id, fresh.links[1].ID, ev.clock.Now())
			},
			"recipient delivery of an incomplete link": func(tx *store.ScopedTx) error {
				return sealer.RecipientDeliveryTx(ctx, tx, ev.a, trf.id, trf.links[1].ID, ev.clock.Now())
			},
			"no tenant": func(tx *store.ScopedTx) error {
				return sealer.DepositTx(ctx, tx, nil, trf.id+"x", ev.clock.Now())
			},
		} {
			err := ev.tx(ev.a, fn)
			if err == nil || name != "no tenant" && !errors.Is(err, ErrNotReady) {
				t.Errorf("%s = %v", name, err)
			}
		}
		// Unknown transfer, and another tenant's transfer.
		other := ev.seed(ev.b, seedOptions{})
		for _, trfID := range []string{other.id, "trf_bogus"} {
			for name, fn := range map[string]func(*store.ScopedTx) error{
				"deposit": func(tx *store.ScopedTx) error { return sealer.DepositTx(ctx, tx, ev.a, trfID, ev.clock.Now()) },
				"overall": func(tx *store.ScopedTx) error { return sealer.OverallDeliveryTx(ctx, tx, ev.a, trfID, ev.clock.Now()) },
				"per link": func(tx *store.ScopedTx) error {
					return sealer.RecipientDeliveryTx(ctx, tx, ev.a, trfID, trf.links[0].ID, ev.clock.Now())
				},
			} {
				if err := ev.tx(ev.a, fn); err == nil || errors.Is(err, ErrNotReady) {
					t.Errorf("%s of %s = %v", name, trfID, err)
				}
			}
		}
	})
}

func TestSealStoreFaults(t *testing.T) {
	t.Parallel()
	ev := newEnv(t, storetest.SQLite(t))
	ctx := t.Context()
	trf := ev.seed(ev.a, seedOptions{noProof: true})
	sealer := ev.prepare()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	// A closed transaction fails every read and write.
	var stale *store.ScopedTx
	if err := ev.tx(ev.a, func(tx *store.ScopedTx) error { stale = tx; return nil }); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"deposit":  sealer.DepositTx(canceled, stale, ev.a, trf.id, ev.clock.Now()),
		"overall":  sealer.OverallDeliveryTx(canceled, stale, ev.a, trf.id, ev.clock.Now()),
		"per link": sealer.RecipientDeliveryTx(canceled, stale, ev.a, trf.id, "rcl_x", ev.clock.Now()),
	} {
		if err == nil {
			t.Errorf("%s on a closed transaction succeeded", name)
		}
	}
	// A sealer whose key is not stored: the insert fails (unknown key).
	bad := &Sealer{db: ev.db, keyID: "psk_01JB0000000000000000000000", priv: sealer.priv}
	if err := ev.tx(ev.a, func(tx *store.ScopedTx) error { return bad.DepositTx(ctx, tx, ev.a, trf.id, ev.clock.Now()) }); err == nil {
		t.Error("deposit with an unknown key succeeded")
	}
	// The statement of a level-less transfer omits the level, and the
	// signature covers the exact stored bytes.
	if err := ev.tx(ev.a, func(tx *store.ScopedTx) error { return sealer.DepositTx(ctx, tx, ev.a, trf.id, ev.clock.Now()) }); err != nil {
		t.Fatal(err)
	}
	p := ev.proofRow(ev.a, trf.id, store.ProofDeposit, "")
	if strings.Contains(string(p.Statement), "confidentialityLevel") ||
		!ed25519.Verify(ev.keys()[0].PublicKey, p.Statement, p.Signature) || sealer.KeyID() != p.KeyID {
		t.Errorf("deposit = %s", p.Statement)
	}
}

func TestSealDeliveryFaults(t *testing.T) {
	t.Parallel()
	ev := newEnv(t, storetest.SQLite(t))
	ctx := t.Context()
	sealer := ev.prepare()

	// A transfer that does not exist cannot be read.
	if err := ev.tx(ev.a, func(tx *store.ScopedTx) error {
		return sealer.OverallDeliveryTx(ctx, tx, ev.a, "trf_01JB0000000000000000000000", ev.clock.Now())
	}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("OverallDeliveryTx(unknown transfer) = %v", err)
	}

	// A transfer downloaded and then deleted is no longer available: its
	// delivery cannot be stated.
	trf := ev.seed(ev.a, seedOptions{noProof: true})
	if err := ev.tx(ev.a, func(tx *store.ScopedTx) error {
		_, err := ev.db.Transfers().MarkFirstDownloadTx(ctx, tx, trf.id, ev.clock.Now(), time.Time{})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// The recipient links cannot be read.
	failing := &Sealer{db: ev.db, keyID: sealer.keyID, priv: sealer.priv, listLinks: func(context.Context, *store.ScopedTx, string) ([]store.RecipientLink, error) {
		return nil, errBoom
	}}
	if err := ev.tx(ev.a, func(tx *store.ScopedTx) error {
		return failing.OverallDeliveryTx(ctx, tx, ev.a, trf.id, ev.clock.Now())
	}); !errors.Is(err, errBoom) {
		t.Errorf("OverallDeliveryTx(links fail) = %v", err)
	}
	ev.end(ev.a, trf.id)
	if err := ev.tx(ev.a, func(tx *store.ScopedTx) error {
		return sealer.OverallDeliveryTx(ctx, tx, ev.a, trf.id, ev.clock.Now())
	}); !errors.Is(err, ErrNotReady) {
		t.Errorf("OverallDeliveryTx(deleted transfer) = %v", err)
	}
}

func TestInsertEncodeFault(t *testing.T) {
	t.Parallel()
	ev := newEnv(t, storetest.SQLite(t))
	sealer := ev.prepare()
	// A file size beyond 2^53 is not representable in the canonical form.
	st := Statement{Kind: store.ProofDeposit, Files: []StatementFile{{Size: 1 << 60}}}
	err := ev.tx(ev.a, func(tx *store.ScopedTx) error {
		return sealer.insert(t.Context(), tx, st, "", ev.clock.Now())
	})
	if err == nil || !strings.Contains(err.Error(), "encode statement") {
		t.Errorf("insert(huge size) = %v", err)
	}
}
