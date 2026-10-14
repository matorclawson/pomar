package seatterm

import (
	"testing"
)

// zeocouncil/the Architect's review of the #128 stack, part A, the pieces
// that belong at the seatterm layer.

// M5: an epoch-fence check-then-act gap. A caller that reads the current
// epoch, then asks for control expecting that exact epoch, must be refused
// if control changed in between (someone else took it), not only if it had
// already changed before the read. The check has to live inside control
// itself, under the session's lock, not as a separate read beforehand.
func TestControlRefusesAStaleExpectedEpoch(t *testing.T) {
	h, _ := newHost(t)
	s, _, err := h.Create("op-epoch", "operator", sh("sleep 30"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.cmd.Process.Kill()
	a, _, _ := s.Attach("a")
	defer a.Detach()
	epoch, err := a.Control(false, "a takes control", nil)
	if err != nil {
		t.Fatal(err)
	}
	expect := epoch
	// Someone else takes control in between a's read and its next Control
	// call: exactly the window M5 is about.
	b, _, _ := s.Attach("b")
	defer b.Detach()
	if _, err := b.Control(true, "b takes control", nil); err != nil {
		t.Fatalf("b's takeover: %v", err)
	}
	if _, err := a.Control(true, "a retakes, expecting the old epoch", &expect); err != ErrEpochStale {
		t.Fatalf("a's stale-epoch control: %v, want ErrEpochStale", err)
	}
	// The expectation matching the CURRENT epoch still succeeds.
	cur := s.Info().Epoch
	if _, err := a.Control(true, "a retakes, expecting the current epoch", &cur); err != nil {
		t.Fatalf("a's current-epoch control: %v", err)
	}
}
