package seatterm

import (
	"strconv"
	"testing"
)

// TestReapedThenStopThenDoneHasNoDataRace is council's own targeted
// reproducer for the s.master lifetime race (POMAR-CC-SOW-37 rev2 F1): for
// each of a hundred quick-exiting sessions, wait for s.reaped to close (the
// leader is gone, its pid free), then call Stop, then wait for Done. This
// exercises exactly the ordering pump() and Stop()'s signal closure race on
// -- s.reaped closing unblocks Stop's foregroundPgrp(s.master) read at the
// same moment pump's own EIO can be closing s.master -- without depending on
// sessiond's shutdown timing, which the earlier
// TestStopAllDoesNotRaceASessionsOwnPump regression (kept as supporting
// evidence, not the required regression) only reproduced unreliably.
func TestReapedThenStopThenDoneHasNoDataRace(t *testing.T) {
	h, _ := newHost(t)
	for i := 0; i < 100; i++ {
		id := "op-race-" + strconv.Itoa(i)
		s, created, err := h.Create(id, "operator", sh("exit 0"))
		if err != nil || !created {
			t.Fatalf("create %d: created=%v err=%v", i, created, err)
		}
		<-s.reaped
		// Stop races pump()'s own forget() (host.go) for the same exited
		// session: "no live session with that ID" means pump won that race
		// and already cleaned up -- a legitimate, race-free outcome, not a
		// failure. What this test actually checks is that neither outcome
		// ever trips the race detector on s.master.
		if _, err := h.Stop(id, "operator", s.ID); err != nil && err.Error() != "no live session with that ID" {
			t.Fatalf("stop %d: %v", i, err)
		}
		<-s.Done()
	}
}
