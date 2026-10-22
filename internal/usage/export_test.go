package usage

// Pending returns the number of pending (tenant, day) entries; 0 for a nil
// recorder.
func (r *Recorder) Pending() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}
