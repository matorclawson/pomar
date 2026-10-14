package sessiond

import (
	"io"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/seatterm"
)

// zeocouncil/the Architect's review of the #128 stack, part A.

// H1: an operation ID's dedupe record must be bound to what it was asked to
// do. Reusing the same ID against a different session (or with different
// text, or a different take) must be refused, never silently replay the
// first call's result onto the second target.
func TestSendRefusesAnOperationIDReusedAgainstADifferentSession(t *testing.T) {
	r := root(t)
	_, c := serve(t, r)
	var a, b Created
	if err := c.Do("POST", "/v1/sessions", shell("op-a", "a", "cat"), &a); err != nil {
		t.Fatal(err)
	}
	if err := c.Do("POST", "/v1/sessions", shell("op-b", "b", "cat"), &b); err != nil {
		t.Fatal(err)
	}
	var out1 opResult
	if err := c.Do("POST", "/v1/sessions/a/send", SendRequest{Operation: "X", Text: "to-a\n"}, &out1); err != nil {
		t.Fatalf("send to a: %v", err)
	}
	if out1.Outcome != "written" {
		t.Fatalf("send to a: outcome %q", out1.Outcome)
	}
	var out2 opResult
	err := c.Do("POST", "/v1/sessions/b/send", SendRequest{Operation: "X", Text: "to-b\n"}, &out2)
	if kindOf(err) != KindConflict {
		t.Fatalf("send to b with the same ID: err=%v out=%+v, want a conflict", err, out2)
	}
	// b never received anything: a's own echo is the only thing on its screen.
	time.Sleep(200 * time.Millisecond)
	scr := screenOf(t, c, "b")
	for _, l := range scr.Lines {
		if l != "" {
			t.Fatalf("session b received input meant for a: %q", scr.Lines)
		}
	}
}

// H1, stop's half: the same operation ID stopping two different sessions.
func TestStopRefusesAnOperationIDReusedAgainstADifferentSession(t *testing.T) {
	r := root(t)
	_, c := serve(t, r)
	var a, b Created
	if err := c.Do("POST", "/v1/sessions", shell("op-a", "a", "sleep 30"), &a); err != nil {
		t.Fatal(err)
	}
	if err := c.Do("POST", "/v1/sessions", shell("op-b", "b", "sleep 30"), &b); err != nil {
		t.Fatal(err)
	}
	var out1 opResult
	if err := c.Do("POST", "/v1/sessions/a/stop", StopRequest{Operation: "X"}, &out1); err != nil {
		t.Fatalf("stop a: %v", err)
	}
	if out1.Outcome != "stopped" {
		t.Fatalf("stop a: outcome %q", out1.Outcome)
	}
	var out2 opResult
	err := c.Do("POST", "/v1/sessions/b/stop", StopRequest{Operation: "X"}, &out2)
	if kindOf(err) != KindConflict {
		t.Fatalf("stop b with the same ID: err=%v out=%+v, want a conflict", err, out2)
	}
	var l Listing
	if err := c.Do("GET", "/v1/sessions", nil, &l); err != nil {
		t.Fatal(err)
	}
	for _, s := range l.Sessions {
		if s.Name == "b" && !s.Running {
			t.Fatal("session b was stopped by an operation ID that was never its own")
		}
	}
}

// The TEST GAP the Architect found by mutation: forcing take=true in send
// left the shipped suite green. A send without -take must be refused while
// someone else controls the session, exactly like an attach is.
func TestSendRefusesWithoutTakeWhileAnotherClientControls(t *testing.T) {
	r := root(t)
	_, c := serve(t, r)
	var created Created
	if err := c.Do("POST", "/v1/sessions", shell("op-1", "a", "cat"), &created); err != nil {
		t.Fatal(err)
	}
	// A separate client attaches and takes control, driving the real v2
	// frame protocol (a bare Attach() alone never completes the resize
	// handshake the server waits on before it calls Control).
	st, err := c.Attach("a", false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	in, inW := io.Pipe()
	defer inW.Close()
	go Pump(st, in, io.Discard, 60, 8, nil, nil)
	var info seatterm.SessionInfo
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if c.Do("GET", "/v1/sessions/a", nil, &info); info.Controller != "" {
			break
		}
	}
	if info.Controller == "" {
		t.Fatal("the attach never took control")
	}
	var out opResult
	err = c.Do("POST", "/v1/sessions/a/send", SendRequest{Operation: "op-2", Text: "hello\n"}, &out)
	if err == nil {
		t.Fatalf("a send without -take was not refused while another client controls: %+v", out)
	}
}

// H2: a create retried after the host's own memory of the operation has
// been pruned (internal/seatterm/host.go's byOp, bounded at 256) must never
// start a second program. 257 short-lived creates evict the host's record
// of the first one; a retry of that first operation must then refuse,
// never orphan whatever currently holds the name.
func TestCreateRefusesARetryAfterTheHostHasPrunedItsOwnRecord(t *testing.T) {
	if os.Getenv("POMAR_SLOW_TESTS") == "" {
		t.Skip("set POMAR_SLOW_TESTS=1: this test drives 257 sequential creates")
	}
	r := root(t)
	_, c := serve(t, r)
	first := CreateRequest{Operation: "op-0", Name: "foo", Path: "/bin/sh", Args: []string{"-c", "true"}, Cols: 20, Rows: 5}
	var firstCreated Created
	if err := c.Do("POST", "/v1/sessions", first, &firstCreated); err != nil {
		t.Fatal(err)
	}
	waitExited := func(name string) {
		for end := time.Now().Add(15 * time.Second); time.Now().Before(end); time.Sleep(2 * time.Millisecond) {
			var info seatterm.SessionInfo
			if c.Do("GET", "/v1/sessions/"+name, nil, &info) == nil && !info.Running {
				return
			}
		}
		t.Fatalf("%s never exited", name)
	}
	waitExited("foo")
	// 256 more distinct, immediately-exiting creates: the host's own byOp
	// remembers at most 256 creations, so op-0's record is evicted once
	// this many later ones have been made. Each waits for its own exit
	// before the next starts, so the live bound (8) is never at issue.
	for i := 1; i <= 256; i++ {
		name := "n" + strconv.Itoa(i)
		req := CreateRequest{Operation: "op-" + strconv.Itoa(i), Name: name, Path: "/bin/sh", Args: []string{"-c", "true"}, Cols: 20, Rows: 5}
		var out Created
		if err := c.Do("POST", "/v1/sessions", req, &out); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		waitExited(name)
	}
	// A legitimate second session takes the name "foo" after the first one
	// has exited: this is not the retry below, a different operation.
	second := CreateRequest{Operation: "op-foo-2", Name: "foo", Path: "/bin/sh", Args: []string{"-c", "sleep 30"}, Cols: 20, Rows: 5}
	var secondCreated Created
	if err := c.Do("POST", "/v1/sessions", second, &secondCreated); err != nil {
		t.Fatalf("the legitimate second create of foo: %v", err)
	}
	if !secondCreated.Created || secondCreated.ID == firstCreated.ID {
		t.Fatalf("the second foo didn't get its own session: %+v", secondCreated)
	}
	// Now retry op-0, the FIRST operation, whose record the host has
	// pruned. sessiond's own (unpruned) memory still says op-0 created
	// "foo", but "foo" now belongs to someone else, running. This must
	// refuse, and must never orphan the real holder.
	var retry Created
	err := c.Do("POST", "/v1/sessions", first, &retry)
	if kindOf(err) != KindConflict {
		t.Fatalf("retrying op-0 after the host pruned it: err=%v out=%+v, want a conflict", err, retry)
	}
	var l Listing
	if err := c.Do("GET", "/v1/sessions", nil, &l); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, s := range l.Sessions {
		if s.Name == "foo" {
			n++
			if s.ID != secondCreated.ID || !s.Running {
				t.Fatalf("foo's real holder was replaced or orphaned: %+v", s)
			}
		}
	}
	if n != 1 {
		t.Fatalf("foo has %d entries, want exactly 1 (no orphaned second program)", n)
	}
}
