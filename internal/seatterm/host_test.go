package seatterm

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// journal is an in-memory audit that can be made to fail.
type journal struct {
	mu   sync.Mutex
	recs []AuditRecord
	fail bool
}

func (j *journal) add(r AuditRecord) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.fail {
		return errors.New("journal full")
	}
	j.recs = append(j.recs, r)
	return nil
}

func (j *journal) has(action, phase, outcome string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, r := range j.recs {
		if r.Action == action && r.Phase == phase && (outcome == "" || r.Outcome == outcome) {
			return true
		}
	}
	return false
}

func sh(script string) SessionSpec {
	return SessionSpec{Name: "agent", Kind: "agent", Command: Command{Path: "/bin/sh", Args: []string{"-c", script}, UID: -1, GID: -1}, Cols: 80, Rows: 24}
}

// collect reads a client's output until it contains want, or fails.
func collect(t *testing.T, c *Client, prefix []byte, want string) []byte {
	t.Helper()
	got := append([]byte(nil), prefix...)
	deadline := time.After(10 * time.Second)
	for !bytes.Contains(got, []byte(want)) {
		select {
		case e := <-c.Events():
			got = append(got, e.Data...)
		case <-deadline:
			t.Fatalf("never saw %q in %q", want, got)
		}
	}
	return got
}

func newHost(t *testing.T) (*SessionHost, *journal) {
	j := &journal{}
	return NewSessionHost(j.add), j
}

// A session's program outlives its clients: detaching never stops it, and
// a new client's snapshot shows what it printed meanwhile.
func TestASessionOutlivesItsClients(t *testing.T) {
	h, j := newHost(t)
	s, created, err := h.Create("op-1", "operator", sh("printf first; sleep 0.5; printf second; sleep 30"))
	if err != nil || !created {
		t.Fatal(err)
	}
	defer s.cmd.Process.Kill()
	c, snap, err := s.Attach("operator")
	if err != nil {
		t.Fatal(err)
	}
	collect(t, c, snap.Data, "first")
	c.Detach()
	time.Sleep(900 * time.Millisecond)
	if !s.Info().Running {
		t.Fatal("detaching stopped the program")
	}
	c2, snap2, err := s.Attach("operator")
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Detach()
	if !strings.Contains(string(snap2.Data), "firstsecond") || !snap2.Complete || snap2.From != 0 {
		t.Fatalf("snapshot %+v %q", snap2, snap2.Data)
	}
	if !j.has("attach", "intent", "") || !j.has("detach", "outcome", "ok") {
		t.Fatal("attach and detach weren't journaled")
	}
}

// Creating is once per operation ID: a retry returns the same session and
// starts no second program.
func TestCreateIsOncePerOperation(t *testing.T) {
	h, _ := newHost(t)
	s1, created1, err := h.Create("op-same", "operator", sh("sleep 30"))
	if err != nil || !created1 {
		t.Fatal(err)
	}
	defer s1.cmd.Process.Kill()
	s2, created2, err := h.Create("op-same", "operator", sh("sleep 30"))
	if err != nil || created2 || s2 != s1 || len(h.List()) != 1 {
		t.Fatalf("a retry made another session: %v %v %d", created2, err, len(h.List()))
	}
}

// Output reaches a client in order: its events start exactly where its
// snapshot ends, with no byte missing or repeated.
func TestSnapshotAndOutputAreOneOrderedStream(t *testing.T) {
	h, _ := newHost(t)
	s, _, err := h.Create("op-2", "operator", sh("i=0; while [ $i -lt 200 ]; do printf 'line-%d\\n' $i; i=$((i+1)); done; sleep 30"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.cmd.Process.Kill()
	time.Sleep(50 * time.Millisecond)
	c, snap, err := s.Attach("operator")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Detach()
	next, got := snap.To, append([]byte(nil), snap.Data...)
	deadline := time.After(10 * time.Second)
	for !bytes.Contains(got, []byte("line-199")) {
		select {
		case e := <-c.Events():
			if e.Offset != next {
				t.Fatalf("event at %d, expected %d", e.Offset, next)
			}
			next += uint64(len(e.Data))
			got = append(got, e.Data...)
		case <-deadline:
			t.Fatal("output never finished")
		}
	}
	for i := 0; i < 200; i++ {
		if bytes.Count(got, []byte("line-"+strconv.Itoa(i)+"\r\n")) != 1 {
			t.Fatalf("line %d is missing or repeated", i)
		}
	}
}

// A viewer types nothing and sizes nothing; the controller's input reaches
// the program.
func TestOnlyTheControllerReachesThePTY(t *testing.T) {
	h, _ := newHost(t)
	s, _, err := h.Create("op-3", "operator", sh("stty -echo; while read l; do printf 'got:%s\\n' \"$l\"; done"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.cmd.Process.Kill()
	viewer, _, _ := s.Attach("viewer")
	defer viewer.Detach()
	if viewer.Input([]byte("x\n")) != ErrNotController || viewer.Resize(100, 30) != ErrNotController {
		t.Fatal("a viewer's input or resize was accepted")
	}
	ctl, snap, _ := s.Attach("operator")
	defer ctl.Detach()
	if _, err := ctl.Control(false, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := viewer.Control(false, "test"); err != ErrControlled {
		t.Fatalf("a second controller was granted: %v", err)
	}
	if err := ctl.Input([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	collect(t, ctl, snap.Data, "got:hello")
	if err := ctl.Resize(100, 30); err != nil {
		t.Fatal(err)
	}
	for d := time.Now().Add(5 * time.Second); time.Now().Before(d); time.Sleep(20 * time.Millisecond) {
		if in := s.Info(); in.Cols == 100 && in.Rows == 30 {
			return
		}
	}
	t.Fatal("the controller's resize never applied")
}

// A takeover fences the old controller at the write itself: its write in
// flight, blocked on a terminal that isn't reading, is cut short; its
// queued input never lands; and only the new controller's input arrives.
func TestATakeoverFencesTheOldControllersQueuedInput(t *testing.T) {
	h, j := newHost(t)
	s, _, err := h.Create("op-4", "operator", sh("stty raw -echo; sleep 2; exec cat"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.cmd.Process.Kill()
	time.Sleep(200 * time.Millisecond)
	a, snap, _ := s.Attach("seat")
	defer a.Detach()
	if _, err := a.Control(false, "test"); err != nil {
		t.Fatal(err)
	}
	filler := bytes.Repeat([]byte("."), MaxData)
	for i := 0; i < 4; i++ { // more than the terminal's input holds: the writer blocks
		if err := a.Input(filler); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Input([]byte("AAAA-STALE")); err != nil {
		t.Fatal(err)
	}
	b, _, _ := s.Attach("operator")
	defer b.Detach()
	start := time.Now()
	if _, err := b.Control(true, "operator takeover"); err != nil {
		t.Fatalf("takeover: %v", err)
	}
	if time.Since(start) > fenceBound+time.Second {
		t.Fatal("the takeover wasn't bounded")
	}
	if a.Input([]byte("late")) != ErrNotController {
		t.Fatal("the old controller could still queue input")
	}
	if err := b.Input([]byte("BBBB-FRESH")); err != nil {
		t.Fatal(err)
	}
	got := collect(t, b, snap.Data, "BBBB-FRESH")
	if bytes.Contains(got, []byte("AAAA-STALE")) {
		t.Fatal("the old controller's queued input landed after the takeover")
	}
	if !j.has("take", "intent", "") || !j.has("take", "outcome", "ok") {
		t.Fatal("the takeover wasn't journaled as intent and outcome")
	}
}

// A grant whose intent can't be journaled is refused; giving control up,
// and detaching, still work when the journal is failing.
func TestNoGrantWithoutItsJournalButRevocationAlways(t *testing.T) {
	h, j := newHost(t)
	s, _, err := h.Create("op-5", "operator", sh("sleep 30"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.cmd.Process.Kill()
	c, _, _ := s.Attach("operator")
	if _, err := c.Control(false, "test"); err != nil {
		t.Fatal(err)
	}
	j.mu.Lock()
	j.fail = true
	j.mu.Unlock()
	other, _, err := s.Attach("seat")
	if err != ErrAudit || other != nil {
		t.Fatalf("an attach was granted without its journal: %v", err)
	}
	c.Release()
	if s.Info().Controller != "" {
		t.Fatal("release was held up by the journal")
	}
	if _, err := c.Control(false, "test"); err != ErrAudit {
		t.Fatalf("a grant without its journal: %v", err)
	}
	c.Detach()
	if len(s.Info().Viewers) != 0 || !s.Info().Running {
		t.Fatal("detach was held up by the journal, or stopped the program")
	}
}

// A client that stops reading falls behind and is told so, never silently
// skipped; a new snapshot resumes it exactly after its cut. The terminal
// keeps draining meanwhile.
func TestAClientThatFallsBehindIsResnapshotted(t *testing.T) {
	h, _ := newHost(t)
	s, _, err := h.Create("op-6", "operator", sh("i=0; while [ $i -lt 4000 ]; do printf '%0200d\\n' $i; i=$((i+1)); done; sleep 30"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.cmd.Process.Kill()
	c, _, _ := s.Attach("viewer")
	defer c.Detach()
	select {
	case <-c.Signals():
	case <-time.After(10 * time.Second):
		t.Fatal("a client that stopped reading was never told it fell behind")
	}
	if !c.Behind() {
		t.Fatal("the client isn't marked behind")
	}
	snap := c.Resnapshot()
	if c.Behind() || len(snap.Data) == 0 {
		t.Fatal("no fresh cut")
	}
	select {
	case e := <-c.Events():
		if e.Offset < snap.To {
			t.Fatalf("output from before the cut: %d < %d", e.Offset, snap.To)
		}
	case <-time.After(5 * time.Second):
		// the program may have finished printing at the cut: that's fine
	}
}

// When the program exits, the session says so with its code, and grants
// nothing more.
func TestAnExitedSessionGrantsNothing(t *testing.T) {
	h, j := newHost(t)
	s, _, err := h.Create("op-7", "operator", sh("exit 3"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the session never ended")
	}
	in := s.Info()
	if in.Running || in.ExitCode == nil || *in.ExitCode != 3 {
		t.Fatalf("state %+v", in)
	}
	c, _, _ := s.Attach("operator")
	if _, err := c.Control(false, "test"); err != ErrSessionExited {
		t.Fatalf("control of an exited session: %v", err)
	}
	if !j.has("exit", "outcome", "ok") {
		t.Fatal("the exit wasn't journaled")
	}
}

// Detaching revokes control and removes the client in one step: a detached
// client controls nothing and queues nothing, whatever it held, and the
// program keeps running (ZEOAPP's review of 6b4691ca, SOW 184).
func TestADetachedClientControlsNothing(t *testing.T) {
	h, _ := newHost(t)
	s, _, err := h.Create("op-8", "operator", sh("sleep 30"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.cmd.Process.Kill()
	c, _, _ := s.Attach("operator")
	if _, err := c.Control(false, "test"); err != nil {
		t.Fatal(err)
	}
	c.Detach()
	if _, err := c.Control(false, "again"); err == nil {
		t.Fatal("a detached client regained control")
	}
	if c.Input([]byte("x")) != ErrNotController || c.Resize(90, 30) != ErrNotController {
		t.Fatal("a detached client queued input or a resize")
	}
	if in := s.Info(); in.Controller != "" || !in.Running {
		t.Fatalf("state after detach: %+v", in)
	}
}

// Detach racing Control on the same client never leaves the client in
// control once both have returned.
func TestDetachRacingControlNeverLeavesADetachedController(t *testing.T) {
	h, _ := newHost(t)
	s, _, err := h.Create("op-9", "operator", sh("sleep 60"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.cmd.Process.Kill()
	for i := 0; i < 300; i++ {
		principal := "client-" + strconv.Itoa(i)
		c, _, err := s.Attach(principal)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); c.Control(false, "race") }()
		go func() { defer wg.Done(); c.Detach() }()
		wg.Wait()
		if in := s.Info(); in.Controller == principal {
			t.Fatalf("round %d: a detached client holds control", i)
		}
		if c.Input([]byte("x")) == nil {
			t.Fatalf("round %d: a detached client queued input", i)
		}
	}
}

// Queued is not written: the outcomes say what reached the program, and
// writes refused for a revoked grant are counted, never resent.
func TestWriteOutcomesAreCounted(t *testing.T) {
	h, _ := newHost(t)
	s, _, err := h.Create("op-10", "operator", sh("stty -echo; while read l; do printf 'got:%s\\n' \"$l\"; done"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.cmd.Process.Kill()
	c, snap, _ := s.Attach("operator")
	defer c.Detach()
	if _, err := c.Control(false, "test"); err != nil {
		t.Fatal(err)
	}
	c.Input([]byte("one\n"))
	c.Resize(100, 30)
	collect(t, c, snap.Data, "got:one")
	for d := time.Now().Add(5 * time.Second); time.Now().Before(d); time.Sleep(20 * time.Millisecond) {
		if o := c.Outcomes(); o.Written == 2 {
			return
		}
	}
	t.Fatalf("outcomes %+v", c.Outcomes())
}
