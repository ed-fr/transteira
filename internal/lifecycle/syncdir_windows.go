package lifecycle

// syncDir does nothing on Windows, which does not support fsync on
// directories: NTFS journals the rename itself.
func syncDir(string) error { return nil }
