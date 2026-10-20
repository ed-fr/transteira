package store_test

import (
	"testing"

	"github.com/ed-fr/transteira/internal/store"
)

func TestDepositorOwns(t *testing.T) {
	internal := store.Transfer{SenderEmail: "alice@entity-a.example.com", SenderKind: store.DepositorInternal}
	external := store.Transfer{
		SenderEmail: "bob@partner.example.org", SenderKind: store.DepositorExternal, InvitationID: "inv_01JAAAAAAAAAAAAAAAAAAAAAAA",
	}
	cases := []struct {
		name string
		d    store.Depositor
		t    store.Transfer
		want bool
	}{
		{"internal sender, address as typed", store.Depositor{Email: " Alice@Entity-A.example.com ", Kind: store.DepositorInternal}, internal, true},
		{"external sender", store.Depositor{Email: "bob@partner.example.org", Kind: store.DepositorExternal, InvitationID: external.InvitationID}, external, true},
		{"other address", store.Depositor{Email: "eve@entity-a.example.com", Kind: store.DepositorInternal}, internal, false},
		{"invalid address", store.Depositor{Email: "not an address", Kind: store.DepositorInternal}, internal, false},
		{"empty depositor", store.Depositor{}, internal, false},
		{"kind mismatch", store.Depositor{Email: "alice@entity-a.example.com", Kind: store.DepositorExternal}, internal, false},
		{"other invitation", store.Depositor{Email: "bob@partner.example.org", Kind: store.DepositorExternal, InvitationID: "inv_01JBBBBBBBBBBBBBBBBBBBBBBB"}, external, false},
		{"external without invitation", store.Depositor{Email: "bob@partner.example.org", Kind: store.DepositorExternal}, external, false},
		{"internal claiming the external", store.Depositor{Email: "bob@partner.example.org", Kind: store.DepositorInternal}, external, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.d.Owns(c.t); got != c.want {
				t.Fatalf("Owns = %v, want %v", got, c.want)
			}
		})
	}
}
