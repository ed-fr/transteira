//go:build unix

package upload

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// oNoFollow makes the open of the state file fail on a symbolic link.
const oNoFollow = syscall.O_NOFOLLOW

// getuid is os.Getuid, replaceable in tests.
var getuid = os.Getuid

// checkStateOwner refuses a state file that others may read or write
// (mode bits 0o077) or that belongs to another user: it holds the
// end-to-end key and decides where the bytes go.
func checkStateOwner(path string, fi fs.FileInfo) error {
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("upload: the state file %s is accessible to other users (mode %04o): make it private (chmod 600) or remove it", path, perm)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int64(st.Uid) != int64(getuid()) {
		return fmt.Errorf("upload: the state file %s belongs to another user (uid %d): remove it", path, st.Uid)
	}
	return nil
}
