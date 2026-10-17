package sessiond

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// council P2: a disconnected adapter's last report is no longer anyone's
// word for the program's current state. Before this fix, a state channel
// that disconnected (the adapter crashed, or was never going to report
// again) left whatever it last said — including "waiting-input" — showing
// forever, which a -when-ready send would have trusted as if the program
// were still actually ready.
func TestAdapterDisconnectResetsAgentStateToUnknown(t *testing.T) {
	_, c := serve(t, root(t))
	req := shell("op-disc", "agent", `printf '%s\n' "$POMAR_SESSION_STATE"; while read l; do printf 'got:%s\n' "$l"; done`)
	req.StateChannel = true
	var made Created
	if err := c.Do("POST", "/v1/sessions", req, &made); err != nil {
		t.Fatalf("create: %v", err)
	}
	path := strings.TrimSpace(waitScreen(t, c, "agent", ".sock").Lines[0])

	var before SessionView
	if err := c.Do("GET", "/v1/sessions/agent", nil, &before); err != nil || before.Agent.State != "unknown" {
		t.Fatalf("no adapter has connected yet: agent state should be unknown: %v %+v", err, before)
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ad := &fakeAdapter{conn: conn, rd: bufio.NewReader(conn)}
	ad.report(t, AdapterReport{State: "waiting-input"})

	var ready SessionView
	for end := time.Now().Add(5 * time.Second); ready.Agent.State != "waiting-input" && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		c.Do("GET", "/v1/sessions/agent", nil, &ready)
	}
	if ready.Agent.State != "waiting-input" {
		t.Fatalf("the report should have been seen: %+v", ready)
	}

	// The adapter disconnects — not superseded by anything, just gone.
	conn.Close()

	var after SessionView
	for end := time.Now().Add(5 * time.Second); after.Agent.State != "unknown" && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		c.Do("GET", "/v1/sessions/agent", nil, &after)
	}
	if after.Agent.State != "unknown" {
		t.Fatalf("a disconnected adapter's stale state must reset to unknown, not keep reading %q", after.Agent.State)
	}

	// A fresh adapter connecting and reporting again works normally after
	// the reset — this isn't a one-way trip into brokenness.
	conn2, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	ad2 := &fakeAdapter{conn: conn2, rd: bufio.NewReader(conn2)}
	ad2.report(t, AdapterReport{State: "running"})
	var again SessionView
	for end := time.Now().Add(5 * time.Second); again.Agent.State != "running" && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		c.Do("GET", "/v1/sessions/agent", nil, &again)
	}
	if again.Agent.State != "running" {
		t.Fatalf("a fresh adapter's report after a reset should be seen: %+v", again)
	}
}

// council P2-1 on #137: the first version of the fix reset state when ANY
// connection disconnected, including an op-only one — exactly the hook
// scripts docs/sessions.md shows, which only ever call begin/finish and
// never send an AdapterReport. Every exit of such a hook was wiping out
// whatever the real adapter had reported. The fix tracks which connection
// actually set the current state (stateConn), separately from which
// connection is merely the latest (conn, used for notices); only that
// exact connection's own disconnect — whether a plain exit or being
// superseded by the next connection — resets anything. This test checks
// both ends: an op-only connection never triggers a reset, however it
// disconnects, and a real reporter's disconnect still correctly does,
// even when it's via supersession rather than a plain close.
func TestAnOpOnlyConnectionNeverResetsAgentState(t *testing.T) {
	_, c := serve(t, root(t))
	req := shell("op-oponly", "agent", `printf '%s\n' "$POMAR_SESSION_STATE"; while read l; do printf 'got:%s\n' "$l"; done`)
	req.StateChannel = true
	var made Created
	if err := c.Do("POST", "/v1/sessions", req, &made); err != nil {
		t.Fatalf("create: %v", err)
	}
	path := strings.TrimSpace(waitScreen(t, c, "agent", ".sock").Lines[0])

	// An op-only connection, as the very first connection: it never
	// touches state at all.
	ops := dialOps(t, path)
	if r := ops.call(t, opRequest{Op: "begin", ID: "op-1", Digest: "d1"}); r["first"] != true {
		t.Fatalf("begin: %+v", r)
	}

	// A real reporter connects next — superseding (closing) the op-only
	// connection above. Its own disconnect must not have left anything
	// behind that disturbs this report.
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ad := &fakeAdapter{conn: conn, rd: bufio.NewReader(conn)}
	ad.report(t, AdapterReport{State: "waiting-input"})
	var state SessionView
	for end := time.Now().Add(5 * time.Second); state.Agent.State != "waiting-input" && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		c.Do("GET", "/v1/sessions/agent", nil, &state)
	}
	if state.Agent.State != "waiting-input" {
		t.Fatalf("the reporter's state should stick, undisturbed by the op-only connection that preceded it: %+v", state)
	}

	// A second op-only connection now supersedes the still-open reporter.
	// The reporter's own disconnect, triggered by that supersession, DOES
	// correctly reset state — it was the one speaking for it, and now
	// it's gone.
	ops2 := dialOps(t, path)
	for end := time.Now().Add(5 * time.Second); state.Agent.State != "unknown" && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		c.Do("GET", "/v1/sessions/agent", nil, &state)
	}
	if state.Agent.State != "unknown" {
		t.Fatalf("the reporter's own disconnect, even via supersession, should still reset state: %+v", state)
	}
	if r := ops2.call(t, opRequest{Op: "begin", ID: "op-2", Digest: "d2"}); r["first"] != true {
		t.Fatalf("begin: %+v", r)
	}

	// A third connection reports a fresh state, superseding the op-only
	// one above. If that op-only connection had incorrectly become
	// stateConn, its own disconnect (triggered by this very supersession)
	// would try to reset — which must lose to this fresh report, never
	// clobber it.
	conn3, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn3.Close()
	ad3 := &fakeAdapter{conn: conn3, rd: bufio.NewReader(conn3)}
	ad3.report(t, AdapterReport{State: "running"})
	for end := time.Now().Add(5 * time.Second); state.Agent.State != "running" && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		c.Do("GET", "/v1/sessions/agent", nil, &state)
	}
	if state.Agent.State != "running" {
		t.Fatalf("a fresh report must never be clobbered by an op-only connection's own disconnect: %+v", state)
	}
}

// council P2-2 on #137: ResetAgentUnknown used to rebuild the whole
// AgentState, losing Accepted along with State and Detail. An acceptance
// is a past fact (the program already confirmed it took an input), not a
// claim about the program's current state; a disconnected adapter no
// longer vouches for "running", but it never un-confirms an input it
// already said was accepted. Before the fix, a disconnect right after an
// acceptance would flip a live input-status read from "yes" back to
// "pending", and a send already waiting in awaitAccepted could settle
// without ever seeing the acceptance it was actually told about.
func TestResetAgentUnknownKeepsAcceptedButClearsState(t *testing.T) {
	_, c := serve(t, root(t))
	req := shell("op-keep-accepted", "agent", `printf '%s\n' "$POMAR_SESSION_STATE"; while read l; do printf 'got:%s\n' "$l"; done`)
	req.StateChannel = true
	var made Created
	if err := c.Do("POST", "/v1/sessions", req, &made); err != nil {
		t.Fatalf("create: %v", err)
	}
	path := strings.TrimSpace(waitScreen(t, c, "agent", ".sock").Lines[0])

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ad := &fakeAdapter{conn: conn, rd: bufio.NewReader(conn)}
	ad.report(t, AdapterReport{State: "waiting-input", Accepted: "in-1"})

	var reported SessionView
	for end := time.Now().Add(5 * time.Second); reported.Agent.Accepted != "in-1" && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		c.Do("GET", "/v1/sessions/agent", nil, &reported)
	}
	if reported.Agent.State != "waiting-input" || reported.Agent.Accepted != "in-1" {
		t.Fatalf("the combined state+accepted report should have been seen: %+v", reported)
	}

	conn.Close()

	var after SessionView
	for end := time.Now().Add(5 * time.Second); after.Agent.State != "unknown" && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		c.Do("GET", "/v1/sessions/agent", nil, &after)
	}
	if after.Agent.State != "unknown" {
		t.Fatalf("state should still reset on disconnect: %+v", after)
	}
	if after.Agent.Accepted != "in-1" {
		t.Fatalf("Accepted is a past fact, not current state: a disconnect must not erase it: %+v", after)
	}
}
