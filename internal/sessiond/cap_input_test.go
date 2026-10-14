package sessiond

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// send refuses outright over its byte bound, never truncating: nothing of
// an over-bound text reaches the program.
func TestSendRefusesOverTheByteBound(t *testing.T) {
	_, c := serve(t, root(t))
	req := shell("op-cap", "agent", `while read l; do printf 'got:%s\n' "$l"; done`)
	var made Created
	if err := c.Do("POST", "/v1/sessions", req, &made); err != nil {
		t.Fatalf("create: %v", err)
	}
	ok := strings.Repeat("a", maxSendBytes-1) // +1 for the trailing \r, exactly at the bound
	if err := c.Do("POST", "/v1/sessions/agent/send", SendRequest{Operation: "cap-ok", Text: ok + "\r"}, nil); err != nil {
		t.Fatalf("at the bound should send: %v", err)
	}
	over := strings.Repeat("a", maxSendBytes+1)
	if err := c.Do("POST", "/v1/sessions/agent/send", SendRequest{Operation: "cap-over", Text: over}, nil); kindOf(err) != KindTooLarge {
		t.Fatalf("over the bound should refuse as too_large: %v", err)
	}
	// Nothing was recorded for the refused ID: a retry refuses the same
	// way, rather than replaying a dedup record from a write that never
	// happened (the bound is checked before begin() ever runs, and before
	// anything reaches the program's PTY).
	if err := c.Do("POST", "/v1/sessions/agent/send", SendRequest{Operation: "cap-over", Text: over}, nil); kindOf(err) != KindTooLarge {
		t.Fatalf("a retry of the refused id refuses again, the same way: %v", err)
	}
}

// A send's live acceptance is read fresh, by input ID, independent of the
// send's own frozen reply: an unknown ID, a pending one, and one the
// adapter has since accepted all read correctly, and a session with no
// state channel says unsupported.
func TestInputStatusReadsLiveAcceptanceByID(t *testing.T) {
	_, c := serve(t, root(t))
	req := shell("op-in", "agent", `printf '%s\n' "$POMAR_SESSION_STATE"; while read l; do printf 'got:%s\n' "$l"; done`)
	req.StateChannel = true
	var made Created
	if err := c.Do("POST", "/v1/sessions", req, &made); err != nil {
		t.Fatalf("create: %v", err)
	}
	path := strings.TrimSpace(waitScreen(t, c, "agent", ".sock").Lines[0])

	var before InputStatusResult
	if err := c.Do("GET", "/v1/sessions/agent/input?id=in-1", nil, &before); err != nil || before.Accepted != "unknown" {
		t.Fatalf("an input never sent is unknown: %v %+v", err, before)
	}

	if err := c.Do("POST", "/v1/sessions/agent/send", SendRequest{Operation: "in-1", Text: "hi\r"}, nil); err != nil {
		t.Fatalf("send: %v", err)
	}
	var pending InputStatusResult
	if err := c.Do("GET", "/v1/sessions/agent/input?id=in-1", nil, &pending); err != nil || pending.Accepted != "pending" {
		t.Fatalf("not yet accepted: %v %+v", err, pending)
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ad := &fakeAdapter{conn: conn, rd: bufio.NewReader(conn)}
	ad.report(t, AdapterReport{Accepted: "in-1"})

	var yes InputStatusResult
	for end := time.Now().Add(5 * time.Second); yes.Accepted != "yes" && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		c.Do("GET", "/v1/sessions/agent/input?id=in-1", nil, &yes)
	}
	if yes.Accepted != "yes" {
		t.Fatalf("a fresh status call should see the acceptance: %+v", yes)
	}

	// A retried send with the same ID still returns its own frozen reply
	// (whatever it recorded when it ran), proving the two reads are
	// genuinely independent: the status call above changed, the send's
	// own reply below did not.
	var retried OpResult
	if err := c.Do("POST", "/v1/sessions/agent/send", SendRequest{Operation: "in-1", Text: "hi\r"}, &retried); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if retried.Accepted != "pending" {
		t.Fatalf("the retried send's own reply is frozen at what it saw when it ran, not the live state: %+v", retried)
	}
}

// A session with no state channel has no notion of acceptance at all:
// every input ID reads unsupported, never unknown or pending.
func TestInputStatusUnsupportedWithoutAStateChannel(t *testing.T) {
	_, c := serve(t, root(t))
	req := shell("op-plain", "plain", `while read l; do printf 'got:%s\n' "$l"; done`)
	var made Created
	if err := c.Do("POST", "/v1/sessions", req, &made); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := c.Do("POST", "/v1/sessions/plain/send", SendRequest{Operation: "p-1", Text: "hi\r"}, nil); err != nil {
		t.Fatalf("send: %v", err)
	}
	var st InputStatusResult
	if err := c.Do("GET", "/v1/sessions/plain/input?id=p-1", nil, &st); err != nil || st.Accepted != "unsupported" {
		t.Fatalf("no state channel: %v %+v", err, st)
	}
}
