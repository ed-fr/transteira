//go:build windows

package diskusage

import "golang.org/x/sys/windows"

// statfs reads the size of the volume holding path and the free space
// available to the calling user (which honors disk quotas).
func statfs(path string) (total, free uint64, err error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, err
	}
	if err := windows.GetDiskFreeSpaceEx(p, &free, &total, nil); err != nil {
		return 0, 0, err
	}
	return total, free, nil
}
