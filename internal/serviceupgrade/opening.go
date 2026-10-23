package serviceupgrade

// sow: pomar-SOW-87. The opening intent ends the reversible window.
import (
	"context"
	"fmt"
	"strings"
)

// OpeningFailure returns the last actually synced phase, rather than claiming
// caller verification was still pending or that admission remains private.
type OpeningFailure struct {
	Journal Journal
	Err     error
}

func (e *OpeningFailure) Error() string { return e.Err.Error() }
func (e *OpeningFailure) Unwrap() error { return e.Err }

func openingPhase(phase string) bool {
	phase = strings.TrimPrefix(phase, "rollback-")
	switch phase {
	case "opening", "opening-draining", "opening-exposing", "opening-releasing", "opening-caller-verifying", "opening-caller-failed", "opening-caller-verified":
		return true
	}
	return false
}

// Every effect has a synced intent. Repeating this after a crash always sets
// the owner's drain again: a restarted manager has lost its in-memory drain.
// These callbacks are fixed product operations, never caller-supplied commands.
func reopenAdmission(ctx context.Context, save func(string) error, drain func(bool) error, expose func() error, caller func() error) error {
	for _, step := range []struct {
		name string
		act  func() error
	}{
		{"draining", func() error { return drain(true) }},
		{"exposing", expose},
		{"releasing", func() error { return drain(false) }},
	} {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := save(step.name); err != nil {
			return err
		}
		if err := step.act(); err != nil {
			return err
		}
	}
	if err := save("caller-verifying"); err != nil {
		return fmt.Errorf("admission opened; caller verification NOT_RUN: %w", err)
	}
	if err := caller(); err != nil {
		persist := save("caller-failed")
		return fmt.Errorf("opened, caller verification FAILED (journal error: %v); no automatic rollback: %w", persist, err)
	}
	if err := save("caller-verified"); err != nil {
		return fmt.Errorf("admission opened and caller checked; verification journal failed: %w", err)
	}
	return nil
}

func preservedObservation(after, before Observation, pin string) error {
	if after.Pin != pin || after.History != before.History || after.ManagerTableHistory != before.ManagerTableHistory || after.KeyID != before.KeyID || after.Capacity != before.Capacity || after.OwnerCapacity != before.OwnerCapacity || after.CallerCapacity != before.CallerCapacity || after.CallerHistory != before.CallerHistory {
		return fmt.Errorf("post-install table/history/key/class/budget/caller identity differs")
	}
	return nil
}
