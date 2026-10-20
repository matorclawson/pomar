package sessiond

import (
	"strconv"
	"testing"
)

// TestStopAllDoesNotRaceASessionsOwnPump is a dedicated regression for the
// data race council and the Architect assigned under POMAR-CC-SOW-37,
// reproduced in the exact shape every real occurrence took (confirmed by
// three separate council -race findings, each in a different test, all
// through this same server-shutdown path): Server.Serve returning calls
// stopAll, which Terminates every session List still reports Running.
// seatterm's TermSession.pump, closing its own master once its command has
// already exited, and Stop's signal closure reading that same master's
// Fd() (via foregroundPgrp, once the session's reaped channel closes) are
// two independent observers of the same process-death event, with no
// order between them otherwise.
//
// A long sequential batch of quick-exiting sessions keeps the tail of the
// batch genuinely racing stopAll when the test returns, even though the
// earlier sessions in the batch finish and are reaped well before then:
// confirmed on this host, this shape reproduces the real race reliably
// across repeated runs (not every single run -- it is a genuine data
// race, not a deterministic bug -- but repeatably, unlike a synthetic
// reimplementation). On unpatched seatterm (internal/seatterm/host.go,
// s.mu removed from both pump's Close and Stop's Fd read), this fails
// under `go test -race` within a handful of runs on this host; with the
// fix, every run is green. -count=10 green on the wider existing suite
// was supporting evidence, not this regression; this test is.
func TestStopAllDoesNotRaceASessionsOwnPump(t *testing.T) {
	_, c := serve(t, root(t))
	for i := 0; i < 200; i++ {
		op := "op-race-stopall-" + strconv.Itoa(i)
		err := c.Do("POST", "/v1/sessions", shell(op, "race-"+strconv.Itoa(i), "exit 0"), &Created{})
		if err != nil && kindOf(err) != KindConflict { // KindConflict: a transient live-session bound, not the point of this test
			t.Fatalf("iteration %d: create: %v", i, err)
		}
	}
	// Deliberately not waiting on any session's exit: the test returns
	// here, at which point the tail of this batch is still alive, and
	// serve's own t.Cleanup cancels the server's context, which calls
	// stopAll while those sessions' pump goroutines are still
	// independently tearing down.
}
