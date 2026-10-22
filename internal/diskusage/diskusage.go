// Package diskusage measures the size and the free space of the filesystem
// holding a path, for the disk space alert of the super admin (CLAUDE.md
// section 19) and the global statistics.
package diskusage

import "fmt"

// Measure returns the total size and the free space, in bytes, of the
// filesystem holding path. Free is the space available to an unprivileged
// process (blocks reserved for the superuser are not counted as free), so
// that free never exceeds total. path must exist.
func Measure(path string) (total, free uint64, err error) {
	total, free, err = statfs(path)
	if err != nil {
		return 0, 0, fmt.Errorf("diskusage: measure %q: %w", path, err)
	}
	return total, min(free, total), nil
}
