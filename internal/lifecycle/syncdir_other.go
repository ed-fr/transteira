//go:build !windows

package lifecycle

import (
	"errors"
	"os"
	"syscall"
)

// syncDir flushes the entries of the directory at path (the rename of a
// copy) to stable storage. A file system that does not support it
// (EINVAL) is not an error.
func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	err = d.Sync()
	if errors.Is(err, syscall.EINVAL) {
		err = nil
	}
	return errors.Join(err, d.Close())
}
