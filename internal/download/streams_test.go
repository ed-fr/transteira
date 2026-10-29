package download

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/ed-fr/transteira/internal/securitylog"
	"github.com/ed-fr/transteira/internal/store/storetest"
)

// wantTooMany fails unless err is a *TooManyStreamsError.
func wantTooMany(t *testing.T, err error) {
	t.Helper()
	var te *TooManyStreamsError
	if !errors.As(err, &te) || !errors.Is(err, ErrTooManyStreams) || te.RetryAfter != StreamRetryAfter {
		t.Fatalf("error %v, want too many streams", err)
	}
}

func TestStreamLimits(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(100), random(100)}})
		ip := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}) }

		// Per transfer: files and archives together, from distinct clients.
		var open []func()
		for i := range MaxStreamsPerTransfer {
			if i%2 == 0 {
				f, err := ev.svc.OpenFile(ctx, ev.a, p.token, ip(i), Cookies{}, p.files[0].ID)
				if err != nil {
					t.Fatal(err)
				}
				open = append(open, func() { _ = f.Content.Close(ctx) })
			} else {
				a, err := ev.svc.PrepareArchive(ctx, ev.a, p.token, ip(i), Cookies{})
				if err != nil {
					t.Fatal(err)
				}
				open = append(open, a.Close)
			}
		}
		_, err := ev.svc.OpenFile(ctx, ev.a, p.token, ip(50), Cookies{}, p.files[1].ID)
		wantTooMany(t, err)
		_, err = ev.svc.PrepareArchive(ctx, ev.a, p.token, ip(50), Cookies{})
		wantTooMany(t, err)
		// Another transfer is not affected.
		q := ev.publish(ev.a, spec{contents: [][]byte{random(100)}})
		ev.fetch(q, "", q.files[0].ID, 0, -1, true)
		// Closing releases the slots, each once.
		open[0]()
		open[0]()
		open[1]()
		open[1]()
		a, err := ev.svc.PrepareArchive(ctx, ev.a, p.token, ip(50), Cookies{})
		if err != nil {
			t.Fatal(err)
		}
		// Write releases the slot.
		if err := a.Write(ctx, discard{}); err != nil {
			t.Fatal(err)
		}
		a.Close()
		ev.fetch(p, "", p.files[1].ID, 0, -1, true)
		for _, c := range open[2:] {
			c()
		}
		if len(ev.svc.streams.counts) != 0 {
			t.Fatalf("slots left: %v", ev.svc.streams.counts)
		}

		// Per client on a transfer: a client cannot take every slot of the
		// transfer, another client still gets one.
		open = nil
		for range MaxStreamsPerTransferClient {
			f, err := ev.svc.OpenFile(ctx, ev.a, p.token, ipTwo, Cookies{}, p.files[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			open = append(open, func() { _ = f.Content.Close(ctx) })
		}
		_, err = ev.svc.PrepareArchive(ctx, ev.a, p.token, ipTwo, Cookies{})
		wantTooMany(t, err)
		f, err := ev.svc.OpenFile(ctx, ev.a, p.token, ipThree, Cookies{}, p.files[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Content.Close(ctx)
		for _, c := range open {
			c()
		}

		// Per client: all transfers of the tenant together, an IPv6 client
		// by its /64.
		var ps []published
		for range MaxStreamsPerClient/MaxStreamsPerTransferClient + 1 {
			ps = append(ps, ev.publish(ev.a, spec{contents: [][]byte{random(10)}}))
		}
		v6 := func(i byte) netip.Addr { return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: i}) }
		open = nil
		for i := range MaxStreamsPerClient {
			q := ps[i/MaxStreamsPerTransferClient]
			f, err := ev.svc.OpenFile(ctx, ev.a, q.token, v6(byte(i)), Cookies{}, q.files[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			open = append(open, func() { _ = f.Content.Close(ctx) })
		}
		last := ps[len(ps)-1]
		_, err = ev.svc.OpenFile(ctx, ev.a, last.token, v6(200), Cookies{}, last.files[0].ID)
		wantTooMany(t, err)
		// The same address in another tenant is another client.
		r := ev.publish(ev.b, spec{contents: [][]byte{random(10)}})
		f, err = ev.svc.OpenFile(ctx, ev.b, r.token, v6(200), Cookies{}, r.files[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Content.Close(ctx)
		for _, c := range open {
			c()
		}

		// A client IP is required.
		_, err = ev.svc.OpenFile(ctx, ev.a, p.token, netip.Addr{}, Cookies{}, p.files[0].ID)
		wantErr(t, err, ErrNoClientIP)
		_, err = ev.svc.PrepareArchive(ctx, ev.a, p.token, netip.Addr{}, Cookies{})
		wantErr(t, err, ErrNoClientIP)
		// A file that cannot be opened releases its slot.
		ev.f.set("open", 1, nil)
		_, err = ev.svc.OpenFile(ctx, ev.a, p.token, ipOne, Cookies{}, p.files[0].ID)
		wantInternal(t, err)
		if len(ev.svc.streams.counts) != 0 {
			t.Fatalf("slots left: %v", ev.svc.streams.counts)
		}
		if !strings.Contains((&TooManyStreamsError{RetryAfter: StreamRetryAfter}).Error(), "30s") ||
			errors.Is(&TooManyStreamsError{}, ErrLocked) {
			t.Error("TooManyStreamsError")
		}
	})
}

// discard is an io.Writer that drops everything.
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func TestStreamEvents(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(10)}})
		var open []func()
		defer func() {
			for _, c := range open {
				c()
			}
		}()
		for range MaxStreamsPerTransferClient {
			a, err := ev.svc.PrepareArchive(ctx, ev.a, p.token, ipOne, Cookies{})
			if err != nil {
				t.Fatal(err)
			}
			open = append(open, a.Close)
		}
		refuse := func(ip netip.Addr) {
			t.Helper()
			_, err := ev.svc.OpenFile(ctx, ev.a, p.token, ip, Cookies{}, p.files[0].ID)
			wantTooMany(t, err)
		}
		events := func() []securitylog.Event {
			var out []securitylog.Event
			for _, e := range ev.seclog.all() {
				if e.Type == securitylog.RateLimited {
					out = append(out, e)
				}
			}
			return out
		}
		// One event per client per interval, whatever the number of
		// refusals.
		refuse(ipOne)
		refuse(ipOne)
		got := events()
		if len(got) != 1 {
			t.Fatalf("%d events, want 1", len(got))
		}
		want := securitylog.Event{
			Type: securitylog.RateLimited, IP: ipOne, Tenant: hostA,
			Fields: []securitylog.Field{{Key: "transfer", Value: p.id[:transferIDLogLen]}, {Key: securitylog.KeyScope, Value: "download_streams"}},
		}
		if !reflect.DeepEqual(got[0], want) {
			t.Fatalf("event %+v, want %+v", got[0], want)
		}
		ev.clock.advance(StreamEventInterval)
		refuse(ipOne)
		if n := len(events()); n != 2 {
			t.Fatalf("%d events after the interval, want 2", n)
		}
		// Another client has its own budget.
		for range MaxStreamsPerTransfer - MaxStreamsPerTransferClient {
			a, err := ev.svc.PrepareArchive(ctx, ev.a, p.token, ipTwo, Cookies{})
			if err != nil {
				t.Fatal(err)
			}
			open = append(open, a.Close)
		}
		refuse(ipThree)
		if got := events(); len(got) != 3 || got[2].IP != ipThree {
			t.Fatalf("events %+v", got)
		}
		// A failing security log does not change the answer.
		ev.seclog.err = errFault
		ev.clock.advance(StreamEventInterval)
		refuse(ipThree)
		ev.seclog.err = nil
		if ev.logs.count("security log write failed") != 1 {
			t.Fatal("security log failure not logged")
		}
	})
}

func TestConcurrentWrongPasswords(t *testing.T) {
	storetest.Run(t, func(t *testing.T, e storetest.Engine) {
		ev := newEnv(t, e, nil)
		ctx := context.Background()
		p := ev.publish(ev.a, spec{contents: [][]byte{random(10)}, password: true})
		const n = 12
		var wg sync.WaitGroup
		errs := make(chan error, n)
		for i := range n {
			wg.Go(func() {
				_, err := ev.svc.Unlock(ctx, ev.a, p.token, netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), "wrong", Cookies{})
				errs <- err
			})
		}
		wg.Wait()
		close(errs)
		wrong, locked := 0, 0
		for err := range errs {
			switch {
			case errors.Is(err, ErrWrongPassword):
				wrong++
			case errors.Is(err, ErrLocked):
				locked++
			default:
				t.Fatalf("unexpected %v", err)
			}
		}
		if v := ev.f.called("verify"); v > 3 || wrong != 2 || locked != n-2 {
			t.Fatalf("%d verifications, %d wrong, %d locked", v, wrong, locked)
		}
	})
}
