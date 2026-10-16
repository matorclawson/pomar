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

// A new connection superseding the old one (serve's own Close, when an
// adapter reconnects before its old connection's read loop even notices)
// is not a disconnect: the old read loop returning afterward must not
// reset state out from under the connection that replaced it.
func TestAdapterSupersessionDoesNotResetTheNewConnectionsState(t *testing.T) {
	_, c := serve(t, root(t))
	req := shell("op-super", "agent", `printf '%s\n' "$POMAR_SESSION_STATE"; while read l; do printf 'got:%s\n' "$l"; done`)
	req.StateChannel = true
	var made Created
	if err := c.Do("POST", "/v1/sessions", req, &made); err != nil {
		t.Fatalf("create: %v", err)
	}
	path := strings.TrimSpace(waitScreen(t, c, "agent", ".sock").Lines[0])

	conn1, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ad1 := &fakeAdapter{conn: conn1, rd: bufio.NewReader(conn1)}
	ad1.report(t, AdapterReport{State: "waiting-input"})
	var ready SessionView
	for end := time.Now().Add(5 * time.Second); ready.Agent.State != "waiting-input" && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		c.Do("GET", "/v1/sessions/agent", nil, &ready)
	}
	if ready.Agent.State != "waiting-input" {
		t.Fatalf("the first report should have been seen: %+v", ready)
	}

	// A second connection arrives without conn1 ever being told to close:
	// the server itself closes conn1 as the superseded one (serve's own
	// policy, not this test's doing).
	conn2, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()

	// Give conn1's read loop every chance to notice its own closure and
	// run its cleanup; state must still read as last reported, never
	// unknown, since conn2 has already taken its place.
	time.Sleep(200 * time.Millisecond)
	var stillReady SessionView
	if err := c.Do("GET", "/v1/sessions/agent", nil, &stillReady); err != nil || stillReady.Agent.State != "waiting-input" {
		t.Fatalf("a superseded connection's cleanup must not reset the new connection's state: %+v", stillReady)
	}
}
