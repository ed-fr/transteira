package transfer

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// TestCheckCreator checks the eligibility rules exported for the one-time
// secrets: the rules of a transfer creation, the reply and drop link
// senders refused without a security event.
func TestCheckCreator(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e)
		ctx := context.Background()
		if email, err := ev.svc.CheckCreator(ctx, ev.a, internalSender()); err != nil || email != alice {
			t.Fatalf("internal: %q, %v", email, err)
		}
		if email, err := ev.svc.CheckCreator(ctx, ev.a, ev.external()); err != nil || email != bob {
			t.Fatalf("external: %q, %v", email, err)
		}
		outside := internalSender()
		outside.ClientIP = externalIP
		if _, err := ev.svc.CheckCreator(ctx, ev.a, outside); !errors.Is(err, ErrForbidden) {
			t.Fatalf("outside: %v", err)
		}
		if got := ev.seclog.reasons(); !slices.Equal(got, []string{securitylog.ReasonIP}) {
			t.Errorf("security log = %v, want the ip refusal", got)
		}
		reply := Sender{
			Depositor: store.Depositor{Email: bob, Kind: store.DepositorReply, ReplyToTransferID: id.New(id.Transfer)},
			ClientIP:  externalIP,
		}
		drop := Sender{
			Depositor: store.Depositor{Email: bob, Kind: store.DepositorDropLink, DropLinkID: id.New(id.DropLink)},
			ClientIP:  externalIP, SessionID: id.New(id.DepositSession),
		}
		for name, s := range map[string]Sender{"reply": reply, "drop link": drop} {
			if _, err := ev.svc.CheckCreator(ctx, ev.a, s); !errors.Is(err, ErrForbidden) {
				t.Errorf("%s: %v", name, err)
			}
		}
		if got := ev.seclog.reasons(); len(got) != 1 {
			t.Errorf("security log = %v, want no event for the reply and drop link senders", got)
		}
	})
}
