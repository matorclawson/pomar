package sessiond

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// dialOps connects to a session's state channel and gives raw op calls.
type opsConn struct {
	conn net.Conn
	rd   *bufio.Reader
}

func dialOps(t *testing.T, path string) *opsConn {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &opsConn{conn: conn, rd: bufio.NewReader(conn)}
}

func (o *opsConn) call(t *testing.T, v any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(v)
	if _, err := o.conn.Write(append(b, '\n')); err != nil {
		t.Fatal(err)
	}
	o.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := o.rd.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if json.Unmarshal(line, &out) != nil {
		t.Fatalf("not JSON: %s", line)
	}
	return out
}

// newAgentSession creates a session with a state channel and returns the
// dialed socket, ready for op calls or state reports, and the socket's own
// path, so a test can redial after a call that ends the connection (an
// error does, by design: the adapter reconnects).
func newAgentSession(t *testing.T, c *Client, name string) (*opsConn, string, Created) {
	t.Helper()
	req := shell("op-"+name, name, `printf '%s\n' "$POMAR_SESSION_STATE"; while read l; do printf 'got:%s\n' "$l"; done`)
	req.Cols, req.StateChannel = 120, true
	var made Created
	if err := c.Do("POST", "/v1/sessions", req, &made); err != nil {
		t.Fatalf("create: %v", err)
	}
	path := strings.TrimSpace(waitScreen(t, c, name, ".sock").Lines[0])
	return dialOps(t, path), path, made
}

// A retry with the same digest is a no-op: first is false, and nothing is
// done twice. A different digest for the same id is refused.
func TestBeginDedupesByDigestAndRefusesAConflict(t *testing.T) {
	_, c := serve(t, root(t))
	o, _, _ := newAgentSession(t, c, "agent")

	r := o.call(t, opRequest{Op: "begin", ID: "op-1", Digest: "d1"})
	if first, _ := r["first"].(bool); !first {
		t.Fatalf("first begin: %+v", r)
	}
	r = o.call(t, opRequest{Op: "begin", ID: "op-1", Digest: "d1"})
	if first, ok := r["first"].(bool); !ok || first {
		t.Fatalf("a retry with the same digest: %+v", r)
	}
	r = o.call(t, opRequest{Op: "begin", ID: "op-1", Digest: "d2"})
	if _, ok := r["error"]; !ok {
		t.Fatalf("a conflicting digest should be refused: %+v", r)
	}
}

// finish(known:false) is permanent: a later finish, either way, on the same
// id is refused, never silently overwritten. Finishing an id never begun
// is refused too.
func TestFinishIsPermanentAndNeedsABegin(t *testing.T) {
	_, c := serve(t, root(t))
	o, path, _ := newAgentSession(t, c, "agent")

	// Each call below that expects an error ends its connection, by
	// design (the adapter reconnects): redial after each.
	known := false
	if r := o.call(t, opRequest{Op: "finish", ID: "never-begun", Known: &known}); r["error"] == nil {
		t.Fatalf("finishing an unbegun id should be refused: %+v", r)
	}
	o = dialOps(t, path)
	o.call(t, opRequest{Op: "begin", ID: "op-2", Digest: "d"})
	if r := o.call(t, opRequest{Op: "finish", ID: "op-2", Known: &known}); r["ok"] != true {
		t.Fatalf("first finish: %+v", r)
	}
	if r := o.call(t, opRequest{Op: "status", ID: "op-2"}); r["disposition"] != "acceptance_unknown" {
		t.Fatalf("status after finish(false): %+v", r)
	}
	yes := true
	if r := o.call(t, opRequest{Op: "finish", ID: "op-2", Known: &yes}); r["error"] == nil {
		t.Fatalf("a second finish should be refused, not flip the disposition: %+v", r)
	}
	o = dialOps(t, path)
	if r := o.call(t, opRequest{Op: "status", ID: "op-2"}); r["disposition"] != "acceptance_unknown" {
		t.Fatalf("the disposition must stay acceptance_unknown: %+v", r)
	}
}

// status on an id never begun is not_found; on a begun-but-unfinished id,
// pending; on a finished one, sent.
func TestStatusReflectsEachDisposition(t *testing.T) {
	_, c := serve(t, root(t))
	o, _, _ := newAgentSession(t, c, "agent")

	if r := o.call(t, opRequest{Op: "status", ID: "unknown-id"}); r["disposition"] != "not_found" {
		t.Fatalf("status of an unbegun id: %+v", r)
	}
	o.call(t, opRequest{Op: "begin", ID: "op-3", Digest: "d"})
	if r := o.call(t, opRequest{Op: "status", ID: "op-3"}); r["disposition"] != "pending" {
		t.Fatalf("status pending: %+v", r)
	}
	known := true
	o.call(t, opRequest{Op: "finish", ID: "op-3", Known: &known})
	if r := o.call(t, opRequest{Op: "status", ID: "op-3"}); r["disposition"] != "sent" {
		t.Fatalf("status sent: %+v", r)
	}
}

// Durability: an operation journal reopened (a restart, simulated directly
// at the level that owns reconciliation) finds any still-pending
// operation and marks it acceptance_unknown, permanently — a restart never
// lets a pending operation look like it quietly became success.
func TestAPendingOperationBecomesUnknownAcrossAReopen(t *testing.T) {
	r := root(t)
	if err := os.MkdirAll(r, 0o700); err != nil {
		t.Fatal(err)
	}
	j, err := openOpJournal(r, "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	if first, err := j.begin("op-a", "d"); err != nil || !first {
		t.Fatalf("begin: %v %v", first, err)
	}
	if first, err := j.begin("op-b", "d"); err != nil || !first {
		t.Fatalf("begin: %v %v", first, err)
	}
	known := true
	if err := j.finish("op-b", known); err != nil {
		t.Fatal(err)
	}
	j.close() // simulates the service ending without op-a ever finishing

	j2, err := openOpJournal(r, "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	defer j2.close()
	if got := j2.status("op-a"); got != opAcceptanceUnknown {
		t.Fatalf("a pending operation across a reopen: got %q, want %q", got, opAcceptanceUnknown)
	}
	if got := j2.status("op-b"); got != opSent {
		t.Fatalf("an already-finished operation must not change on reopen: got %q", got)
	}
	// The conversion is itself durable: a third open sees the same thing,
	// not a repeated, different conversion.
	j2.close()
	j3, err := openOpJournal(r, "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	defer j3.close()
	if got := j3.status("op-a"); got != opAcceptanceUnknown {
		t.Fatalf("the conversion itself must be durable: got %q", got)
	}
}

// The bound evicts sent entries oldest first, and never touches a pending
// or acceptance_unknown one.
func TestTheBoundEvictsSentEntriesNeverHeldOnes(t *testing.T) {
	r := root(t)
	if err := os.MkdirAll(r, 0o700); err != nil {
		t.Fatal(err)
	}
	const bound = 50 // this instance only: a shared constant would make the test slow
	j, err := openOpJournalBound(r, "sess-2", bound)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	// A pending and an acceptance_unknown entry, first: these must survive
	// everything that follows.
	j.begin("held-pending", "d")
	j.begin("held-unknown", "d")
	known := false
	j.finish("held-unknown", known)
	// Fill well past the bound with sent entries.
	yes := true
	for i := 0; i < bound+20; i++ {
		id := "sent-" + strconv.Itoa(i)
		j.begin(id, "d")
		j.finish(id, yes)
	}
	if got := j.status("held-pending"); got != opPending {
		t.Fatalf("a pending entry was evicted: %q", got)
	}
	if got := j.status("held-unknown"); got != opAcceptanceUnknown {
		t.Fatalf("an acceptance_unknown entry was evicted: %q", got)
	}
	if got := j.status("sent-0"); got != "not_found" {
		t.Fatalf("the oldest sent entry should have been evicted: %q", got)
	}
	if got := j.status("sent-" + strconv.Itoa(bound+19)); got != opSent {
		t.Fatalf("the newest sent entry should still be there: %q", got)
	}
}

// show lists a session's held (acceptance_unknown) operations with their
// age, so an attaching client sees them before typing anything.
func TestShowListsHeldOperationsWithAge(t *testing.T) {
	_, c := serve(t, root(t))
	o, _, _ := newAgentSession(t, c, "agent")

	o.call(t, opRequest{Op: "begin", ID: "held-1", Digest: "d"})
	known := false
	o.call(t, opRequest{Op: "finish", ID: "held-1", Known: &known})
	o.call(t, opRequest{Op: "begin", ID: "sent-1", Digest: "d"})
	yes := true
	o.call(t, opRequest{Op: "finish", ID: "sent-1", Known: &yes})

	var v SessionView
	if err := c.Do("GET", "/v1/sessions/agent", nil, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.HeldOperations) != 1 || v.HeldOperations[0].ID != "held-1" {
		t.Fatalf("held_operations: %+v", v.HeldOperations)
	}
}
