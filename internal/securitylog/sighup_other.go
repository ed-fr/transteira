//go:build !unix

package securitylog

import "context"

// HandleSIGHUP is a no-op on platforms without SIGHUP (Windows). Production
// images run on Linux; see the Unix implementation. The returned stop
// function does nothing and may be called any number of times.
func (*Logger) HandleSIGHUP(context.Context) (stop func()) {
	return func() {}
}
