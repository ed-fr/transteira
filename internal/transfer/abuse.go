package transfer

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/tenant"
)

// AbuseFacts describe a transfer for the abuse detection rules (CLAUDE.md
// section 15). It mirrors abuse.Facts field by field: package transfer does
// not import package abuse, and the application wiring converts between
// the two (see [AbuseChecker]).
type AbuseFacts struct {
	// TransferID is the identifier of the created transfer, "" when the
	// creation is being checked or was refused.
	TransferID string
	// SenderEmail is the normalized sender address (the address given in
	// senderEmail for an API token).
	SenderEmail string
	// Kind is the depositor kind of the sender (an API token counts as
	// store.DepositorInternal).
	Kind store.DepositorKind
	// Bytes is the declared total of the transfer.
	Bytes int64
	// Recipients are the normalized recipients: the inviter for an external
	// sender.
	Recipients []string
	// At is the creation time.
	At time.Time
	// ClientIP is the real client IP of the request.
	ClientIP netip.Addr
}

// AbuseBlock is a creation refused by the abuse detection: the tenant
// blocks on exceed and the blocking rule Rule is exceeded. It mirrors
// abuse.Block.
type AbuseBlock struct {
	// Rule is the exceeded rule.
	Rule store.AbuseRule
	// Value is the value the transfer would have reached.
	Value float64
	// Threshold is the threshold of the rule.
	Threshold float64
	// Opaque is detector data the checker returns from CheckCreateTx and
	// gets back, untouched, in Blocked (the wiring keeps there what the
	// detector needs to record the refusal).
	Opaque any
}

// AbuseChecker is the part of the abuse detector (package abuse) the
// service uses, in the types of this package. The application wires a small
// adapter around *abuse.Detector that converts AbuseFacts to abuse.Facts
// and abuse.Block to AbuseBlock, so that package transfer stays independent
// of package abuse.
type AbuseChecker interface {
	// CheckCreateTx runs inside the creation transaction, under the tenant
	// lock, so that two concurrent creations cannot both pass a limit. It
	// returns a non-nil block when the creation must be refused. It never
	// writes.
	CheckCreateTx(ctx context.Context, tx *store.ScopedTx, t *tenant.Tenant, f AbuseFacts) (*AbuseBlock, error)
	// Blocked records a refused creation after the rollback (audit and
	// deduplicated alert). Best effort: it never fails.
	Blocked(ctx context.Context, t *tenant.Tenant, f AbuseFacts, b AbuseBlock)
	// AfterCreate evaluates every rule for a committed creation and alerts.
	// Best effort: it never fails.
	AfterCreate(ctx context.Context, t *tenant.Tenant, f AbuseFacts)
}

// errAbuse aborts the creation transaction on an abuse block.
var errAbuse = errors.New("transfer: abuse threshold exceeded")
