package quota

// Pending returns the number of tenants waiting for an evaluation
// requested by [Monitor.Check].
func (m *Monitor) Pending() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.pending)
}
