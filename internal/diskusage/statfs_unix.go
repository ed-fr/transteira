//go:build linux || darwin

package diskusage

import "golang.org/x/sys/unix"

// statfs reads the size and the space available to unprivileged users of
// the filesystem holding path.
func statfs(path string) (total, free uint64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bsize := toUint64(st.Bsize)
	return toUint64(st.Blocks) * bsize, toUint64(st.Bavail) * bsize, nil
}

// toUint64 converts a statfs field, whose integer type differs between
// systems. The kernel never reports a negative block size or count.
func toUint64[T ~int64 | ~uint64 | ~uint32](v T) uint64 {
	return uint64(v)
}
