package manager

// sow: pomar-SOW-87. Terminal compute and completion evidence have distinct
// lifetimes. No publication state requires retaining the disposable VM object.

// cleanupTerminalVMs reserves original entries before dropping m.mu. Remove
// cannot erase a reserved entry and allow a new same-name attempt to be mistaken
// for its predecessor while a potentially slow venue removal is in progress.
// Failed cleanup is retried on the next recovery poll; evidence is never removed.
func (m *Manager) cleanupTerminalVMs() {
	m.cleanupTerminalVMsWith(m.teardownVM)
}

// The fixed production remover is supplied above. Package tests can pause this
// local boundary without a global hook, filesystem race, or public API knob.
func (m *Manager) cleanupTerminalVMsWith(teardown func(string)) {
	m.mu.Lock()
	var work []*Entry
	for _, e := range m.t.entries {
		if e.Terminal() && !e.terminalCleanup {
			e.terminalCleanup = true
			work = append(work, e)
		}
	}
	m.mu.Unlock()
	for _, e := range work {
		teardown(e.Attempt)
		m.mu.Lock()
		if m.t.entries[e.Attempt] == e {
			e.terminalCleanup = false
		}
		m.mu.Unlock()
	}
}
