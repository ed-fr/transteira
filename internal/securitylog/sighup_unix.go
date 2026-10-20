//go:build unix

package securitylog

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// HandleSIGHUP reopens the log file each time the process receives SIGHUP
// (sent by logrotate's postrotate script), until ctx is done or the
// returned stop function is called. It returns at once; the work happens in
// a goroutine. Reopen errors go to the handler set by [WithErrorHandler],
// except [ErrClosed] (a signal racing with shutdown), which is ignored.
//
// stop stops signal delivery and waits for the goroutine to exit, so that
// no reopening runs after it returns; call it before [Logger.Close]. It is
// safe to call several times and after ctx is done.
func (l *Logger) HandleSIGHUP(ctx context.Context) (stop func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.reopenOn(ctx, sig)
	}()
	return sync.OnceFunc(func() {
		signal.Stop(sig)
		cancel()
		<-done
	})
}
