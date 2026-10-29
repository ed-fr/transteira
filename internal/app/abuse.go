package app

import (
	"context"

	"github.com/ed-fr/transteira/internal/abuse"
	"github.com/ed-fr/transteira/internal/mytransfers"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
	"github.com/ed-fr/transteira/internal/transfer"
)

// The services that feed the abuse detector (packages transfer and
// mytransfers) declare their own mirror types of abuse.Facts and abuse.Block
// so that they never import package abuse; the adapters below convert them.

// createAbuse adapts the detector to transfer.AbuseChecker.
type createAbuse struct {
	d *abuse.Detector
}

var _ transfer.AbuseChecker = createAbuse{}

// toAbuseFacts converts the facts of a creation.
func toAbuseFacts(f transfer.AbuseFacts) abuse.Facts {
	return abuse.Facts{
		TransferID: f.TransferID, SenderEmail: f.SenderEmail, Kind: f.Kind, Bytes: f.Bytes,
		Recipients: f.Recipients, At: f.At, ClientIP: f.ClientIP,
	}
}

// CheckCreateTx implements transfer.AbuseChecker. The *abuse.Block of the
// detector travels in AbuseBlock.Opaque, so that Blocked hands the very
// same value back (it keeps an unexported field).
func (a createAbuse) CheckCreateTx(ctx context.Context, tx *store.ScopedTx, t *tenant.Tenant, f transfer.AbuseFacts) (*transfer.AbuseBlock, error) {
	b, err := a.d.CheckCreateTx(ctx, tx, t, toAbuseFacts(f))
	if err != nil || b == nil {
		return nil, err
	}
	return &transfer.AbuseBlock{Rule: b.Rule, Value: b.Value, Threshold: b.Threshold, Opaque: *b}, nil
}

// Blocked implements transfer.AbuseChecker.
func (a createAbuse) Blocked(ctx context.Context, t *tenant.Tenant, f transfer.AbuseFacts, b transfer.AbuseBlock) {
	blk, ok := b.Opaque.(abuse.Block)
	if !ok {
		// Not produced by CheckCreateTx: rebuild it from the public fields.
		blk = abuse.Block{Rule: b.Rule, Value: b.Value, Threshold: b.Threshold}
	}
	a.d.Blocked(ctx, t, toAbuseFacts(f), blk)
}

// AfterCreate implements transfer.AbuseChecker.
func (a createAbuse) AfterCreate(ctx context.Context, t *tenant.Tenant, f transfer.AbuseFacts) {
	a.d.AfterCreate(ctx, t, toAbuseFacts(f))
}

// extendAbuse adapts the detector to mytransfers.AbuseNotifier.
type extendAbuse struct {
	d *abuse.Detector
}

var _ mytransfers.AbuseNotifier = extendAbuse{}

// AfterExtend implements mytransfers.AbuseNotifier.
func (a extendAbuse) AfterExtend(ctx context.Context, t *tenant.Tenant, f mytransfers.AbuseFacts) {
	a.d.AfterExtend(ctx, t, abuse.Facts{
		TransferID: f.TransferID, SenderEmail: f.SenderEmail, Kind: f.Kind, Bytes: f.Bytes,
		Recipients: f.Recipients, At: f.At, ClientIP: f.ClientIP,
	})
}
