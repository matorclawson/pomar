package seatterm

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func sha256OfFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// A matching ExpectedSHA256 launches normally; a mismatch refuses the
// launch outright, before anything runs.
func TestExpectedSHA256PinsTheExactBinary(t *testing.T) {
	h, _ := newHost(t)
	spec := sh("echo ok")
	spec.Command.ExpectedSHA256 = sha256OfFile(t, "/bin/sh")
	s, _, err := h.Create("op-sha-1", "operator", spec)
	if err != nil {
		t.Fatalf("a matching hash should launch: %v", err)
	}
	collect(t, mustAttach(t, s, "v"), nil, "ok")

	spec2 := sh("echo ok")
	spec2.Command.ExpectedSHA256 = strings.Repeat("0", 64)
	if _, _, err := h.Create("op-sha-2", "operator", spec2); err == nil {
		t.Fatal("a mismatched hash should refuse the launch")
	}
}

func mustAttach(t *testing.T, s *TermSession, principal string) *Client {
	t.Helper()
	c, _, err := s.Attach(principal)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Health is a passive, heuristic read of the current screen: it fires on
// each pattern and nothing else, and never on an ordinary screen.
func TestHealthPatternsAreHeuristicNotAuthoritative(t *testing.T) {
	h, _ := newHost(t)
	s, _, err := h.Create("op-health-1", "operator", sh(`printf 'all good\n'; sleep 30`))
	if err != nil {
		t.Fatal(err)
	}
	c := mustAttach(t, s, "v")
	collect(t, c, nil, "all good")
	if hl := s.Health(); hl.PossiblePanic || hl.PossibleReadonlyRefusal || hl.PossibleApprovalPrompt {
		t.Fatalf("an ordinary screen shouldn't trip any pattern: %+v", hl)
	}

	s2, _, err := h.Create("op-health-2", "operator", sh(`printf 'panic: boom\n'; sleep 30`))
	if err != nil {
		t.Fatal(err)
	}
	c2 := mustAttach(t, s2, "v")
	collect(t, c2, nil, "panic: boom")
	if hl := s2.Health(); !hl.PossiblePanic || hl.PossibleReadonlyRefusal || hl.PossibleApprovalPrompt {
		t.Fatalf("a panic screen should trip only possible_panic: %+v", hl)
	}

	s3, _, err := h.Create("op-health-3", "operator", sh(`printf 'touch: read-only file system\n'; sleep 30`))
	if err != nil {
		t.Fatal(err)
	}
	c3 := mustAttach(t, s3, "v")
	collect(t, c3, nil, "read-only")
	if hl := s3.Health(); hl.PossiblePanic || !hl.PossibleReadonlyRefusal || hl.PossibleApprovalPrompt {
		t.Fatalf("a read-only refusal should trip only possible_readonly_refusal: %+v", hl)
	}

	s4, _, err := h.Create("op-health-4", "operator", sh(`printf 'Do you want to proceed?\n'; sleep 30`))
	if err != nil {
		t.Fatal(err)
	}
	c4 := mustAttach(t, s4, "v")
	collect(t, c4, nil, "proceed")
	if hl := s4.Health(); hl.PossiblePanic || hl.PossibleReadonlyRefusal || !hl.PossibleApprovalPrompt {
		t.Fatalf("an approval prompt should trip only possible_approval_prompt: %+v", hl)
	}
}

// Scrollback gives the lines scrolled off the screen, oldest first,
// readable without attaching, and -lines bounds it to the most recent.
func TestScrollbackGivesHistoryBeyondTheScreen(t *testing.T) {
	h, _ := newHost(t)
	spec := sh(`i=1; while [ $i -le 20 ]; do printf 'line%02d\n' $i; i=$((i+1)); done; sleep 30`)
	spec.Rows = 4
	s, _, err := h.Create("op-scroll-1", "operator", spec)
	if err != nil {
		t.Fatal(err)
	}
	c := mustAttach(t, s, "v")
	collect(t, c, nil, "line20")

	sb := s.Scrollback(0)
	if len(sb.Lines) == 0 {
		t.Fatal("no scrollback: the screen is only 4 rows but 20 lines were printed")
	}
	found1, found20 := false, false
	for _, l := range sb.Lines {
		if l == "line01" {
			found1 = true
		}
		if l == "line20" {
			found20 = true
		}
	}
	if !found1 {
		t.Fatalf("the earliest scrolled line is missing: %v", sb.Lines)
	}
	if found20 {
		t.Fatalf("the last lines are still on screen, not scrollback: %v", sb.Lines)
	}

	limited := s.Scrollback(2)
	if len(limited.Lines) != 2 || !limited.Truncated {
		t.Fatalf("-lines should bound and flag truncation: %+v", limited)
	}
	full := s.Scrollback(0)
	if limited.Lines[0] != full.Lines[len(full.Lines)-2] || limited.Lines[1] != full.Lines[len(full.Lines)-1] {
		t.Fatalf("a bounded read should be the most recent lines: got %v, want the tail of %v", limited.Lines, full.Lines)
	}
}
