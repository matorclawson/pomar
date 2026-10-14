package seatterm

import "strings"

// Health is a passive, read-only diagnostic read of a session's current
// screen, for criterion 14 of the tmux-replacement acceptance (remote seat
// health, without the seat's cooperation): a seat whose adapter can't speak
// at all still has a screen the session layer can look at.
//
// Every field here is heuristic, not authoritative. It is a fixed,
// documented list of substrings matched against rendered text, nothing
// more: it can miss a real failure that doesn't match a known string, and
// it can misfire on a string that merely appears in something the program
// is displaying (a file being viewed, say). It is never fed back into any
// control or readiness decision, and it never substitutes for the
// adapter-reported agent state (AgentState) when an adapter can speak at
// all: that stays the authoritative signal. This is only what's still
// visible when it can't.
type Health struct {
	PossiblePanic           bool   `json:"possible_panic"`
	PossibleReadonlyRefusal bool   `json:"possible_readonly_refusal"`
	PossibleApprovalPrompt  bool   `json:"possible_approval_prompt"`
	LastOutput              string `json:"last_output,omitempty"`
}

// These lists are a starting point, not exhaustive: amend them as real
// failures are found that don't match, rather than claiming completeness.
var (
	panicMarkers = []string{
		"panic:",                            // Go
		"Traceback (most recent call last)", // Python, in case a guest tool prints one
		"Unhandled exception",               // Node/.NET style
		"goroutine ",                        // a Go stack trace, alongside "panic:"
	}
	readonlyMarkers = []string{
		"read-only file system",
		"Read-only file system",
		"Permission denied",
		"EROFS",
	}
	approvalMarkers = []string{
		"proceed?",
		"Do you want to",
		"approve",
		"(y/n)",
		"[y/N]",
		"[Y/n]",
	}
)

func containsAny(lines []string, markers []string) bool {
	for _, l := range lines {
		for _, m := range markers {
			if strings.Contains(l, m) {
				return true
			}
		}
	}
	return false
}

// Health runs the pattern checks against the session's current screen (its
// visible rows; a marker scrolled into history isn't read back for this).
func (s *TermSession) Health() Health {
	scr := s.Screen()
	in := s.Info()
	return Health{
		PossiblePanic:           containsAny(scr.Lines, panicMarkers),
		PossibleReadonlyRefusal: containsAny(scr.Lines, readonlyMarkers),
		PossibleApprovalPrompt:  containsAny(scr.Lines, approvalMarkers),
		LastOutput:              in.LastOutput,
	}
}
