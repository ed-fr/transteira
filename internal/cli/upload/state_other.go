//go:build !unix

package upload

import "io/fs"

// oNoFollow is 0 where O_NOFOLLOW does not exist: the Lstat check and the
// identity check after the open remain.
const oNoFollow = 0

// checkStateOwner accepts any owner and mode: Windows has no Unix modes,
// and the state file must be kept in a private directory there (see the
// package documentation).
func checkStateOwner(string, fs.FileInfo) error { return nil }
