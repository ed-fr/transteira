package app

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ed-fr/transteira/internal/abuse"
	"github.com/ed-fr/transteira/internal/audit"
	"github.com/ed-fr/transteira/internal/mail"
	"github.com/ed-fr/transteira/internal/mytransfers"
	"github.com/ed-fr/transteira/internal/notify"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/transfer"
)

// abuseNotifier and abuseMailer count the alert mails of the detector.
type abuseNotifier struct{ alerts int }

func (n *abuseNotifier) AbuseAlert(context.Context, *tenant.Tenant, mail.AbuseAlertData, []notify.Contact) ([]mail.Job, error) {
	n.alerts++
	return nil, nil
}

func (n *abuseNotifier) AbuseReport(context.Context, *tenant.Tenant, mail.AbuseReportData, []notify.Contact) ([]mail.Job, error) {
	return nil, nil
}

type abuseMailer struct{}

func (abuseMailer) Send(context.Context, []mail.Job, ...slog.Attr) {}

// TestAbuseAdapters runs the adapters of package app over a real detector:
// the block of CheckCreateTx travels in Opaque and comes back to Blocked,
// the other calls reach the detector.
func TestAbuseAdapters(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ctx := context.Background()
		db, err := store.Open(ctx, e.Config())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		notifier := &abuseNotifier{}
		det, err := abuse.New(db, notifier, abuseMailer{}, audit.New(db), abuse.Options{AdminLink: "https://admin.example.com/admin"})
		if err != nil {
			t.Fatal(err)
		}
		tn, err := db.Tenants().Create(ctx, &tenant.Tenant{
			Name: "Entity A", FQDN: "transfer.entity-a.example.com", DefaultLanguage: "en",
			MaxTransferBytes: 1 << 34, StorageQuotaBytes: 1 << 40,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.NetworkRules().Replace(ctx, tn.ID, nil, []string{"entity-a.example.com"}); err != nil {
			t.Fatal(err)
		}
		s := store.DefaultAbuseSettings()
		one := 1
		s.MaxRecipientsPerTransfer, s.BlockOnExceed = &one, true
		if _, err := db.AbuseSettings().Put(ctx, tn.ID, s); err != nil {
			t.Fatal(err)
		}

		a := createAbuse{d: det}
		facts := transfer.AbuseFacts{
			SenderEmail: "alice@entity-a.example.com", Kind: store.DepositorInternalRemote, Bytes: 10,
			Recipients: []string{"b@example.net", "c@example.net"}, At: time.Now(), ClientIP: netip.MustParseAddr("192.0.2.7"),
		}
		scoped, err := db.Scoped(tn.ID)
		if err != nil {
			t.Fatal(err)
		}
		var block *transfer.AbuseBlock
		if err := scoped.Tx(ctx, func(tx *store.ScopedTx) error {
			var err error
			block, err = a.CheckCreateTx(ctx, tx, tn, facts)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if block == nil || block.Rule != store.AbuseRuleRecipients || block.Value != 2 || block.Threshold != 1 {
			t.Fatalf("block = %+v", block)
		}
		if _, ok := block.Opaque.(abuse.Block); !ok {
			t.Errorf("Opaque = %T, want the detector block", block.Opaque)
		}
		// One recipient: nothing to refuse.
		facts1 := facts
		facts1.Recipients = facts.Recipients[:1]
		var none *transfer.AbuseBlock
		if err := scoped.Tx(ctx, func(tx *store.ScopedTx) error {
			var err error
			none, err = a.CheckCreateTx(ctx, tx, tn, facts1)
			return err
		}); err != nil || none != nil {
			t.Fatalf("no block expected: %+v %v", none, err)
		}
		// The refusal is recorded, with the opaque block and without it.
		a.Blocked(ctx, tn, facts, *block)
		a.Blocked(ctx, tn, facts, transfer.AbuseBlock{Rule: store.AbuseRuleRecipients, Value: 2, Threshold: 1})
		a.AfterCreate(ctx, tn, facts)
		extend := extendAbuse{d: det}
		extend.AfterExtend(ctx, tn, mytransfers.AbuseFacts{
			TransferID: "trf_x", SenderEmail: facts.SenderEmail, Kind: facts.Kind, Bytes: 10,
			Recipients: facts.Recipients, At: facts.At, ClientIP: facts.ClientIP,
		})
	})
}

// TestRunServesAbuseOperations checks that the abuse operations are wired:
// the report of an abuse (public, same-origin protected, answered by the
// download service) and the administration of the thresholds (answered
// 401 without session, not by a stub).
func TestRunServesAbuseOperations(t *testing.T) {
	t.Parallel()
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		cfg := testConfig(t, e)
		prepare(t, cfg)
		cfg.ClamAV.Address = fakeClamd(t)
		s := start(t, cfg)
		const link = "/api/v1/downloads/dl_Xk4Lm9Qp2Zr7Vb1Nt6Yc3Hd8Jf/abuse-reports"
		// The test connection has no client IP the service could use, so the
		// report cannot succeed here: it must at least reach the service
		// (not the 404 of a stub) once past the cross-site checks.
		code, body := s.do(t, http.MethodPost, link, tenantHost, strings.NewReader(`{"category":"spam"}`))
		if code == http.StatusNotFound || code == http.StatusForbidden {
			t.Errorf("report = %d %s", code, body)
		}
		if code, body := s.get(t, "/api/v1/admin/tenants/ten_x/abuse-thresholds", adminHost); code != http.StatusUnauthorized {
			t.Errorf("thresholds without session = %d %s", code, body)
		}
	})
}
