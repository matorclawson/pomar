package webservice

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// memoryStore models the required atomic durable boundary and detached reads.
// Reconstructing Engine with the same store simulates process loss, not native
// filesystem durability or systemd qualification.
type memoryStore struct {
	mu        sync.Mutex
	s         State
	fail      bool
	loseReply bool
}

func clone(s State) State {
	b, _ := json.Marshal(s)
	var out State
	_ = json.Unmarshal(b, &out)
	return out
}

func (m *memoryStore) Load() (State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return clone(m.s), nil
}

func (m *memoryStore) CompareAndSwap(rev uint64, s State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.s.Revision != rev {
		return ErrConflict
	}
	if m.fail {
		return errors.New("injected commit failure")
	}
	m.s = clone(s)
	if m.loseReply {
		return errors.New("injected lost commit reply")
	}
	return nil
}

func hash(c string) string { return strings.Repeat(c, 64) }

func fixture() (*memoryStore, Request) {
	m := &memoryStore{s: State{Epoch: 7, Current: hash("a"), Database: hash("d")}}
	r := Request{ID: "update-1", Epoch: 7, ExpectedPrevious: hash("a"), Release: hash("b"), Profile: hash("c"), Database: hash("d")}
	return m, r
}

func advance(t *testing.T, e Engine, op Operation, k EventKind) Operation {
	t.Helper()
	v := Event{ID: op.Request.ID, Epoch: op.Request.Epoch, From: op.Phase, Kind: k}
	if k != RequestMaintenance && k != RequestAPI {
		v.Evidence = hash("e")
	}
	next, err := e.Advance(v)
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func TestFixedPortSingleWriterOrderAndDatabaseRetention(t *testing.T) {
	m, r := fixture()
	e := Engine{Store: m}
	op, err := e.Begin(r)
	if err != nil {
		t.Fatal(err)
	}
	steps := []EventKind{RequestMaintenance, MaintenanceClosed, PreviousDeparted, RequestAPI, APIHealthy, WebHealthy, RouteHealthy}
	for i, k := range steps {
		// Starting the API before complete old-writer departure is refused.
		if i < 3 {
			_, err := e.Advance(Event{ID: r.ID, Epoch: r.Epoch, From: op.Phase, Kind: RequestAPI})
			if err == nil {
				t.Fatalf("API start allowed in %s", op.Phase)
			}
		}
		op = advance(t, e, op, k)
		s, _ := m.Load()
		if s.Database != r.Database || s.Revision != uint64(i+2) {
			t.Fatalf("database or revision changed incorrectly: %+v", s)
		}
		if i < len(steps)-1 && (s.Current != r.ExpectedPrevious || s.Active != r.ID) {
			t.Fatal("published candidate or released fence before route observation")
		}
	}
	s, _ := m.Load()
	if op.Phase != Complete || s.Current != r.Release || s.Active != "" || len(op.History) != len(steps) {
		t.Fatalf("wrong terminal record: %+v", s)
	}
	// Retry after completion must return the original, despite changed current.
	got, err := (Engine{Store: m}).Begin(r)
	if err != nil || got.Phase != Complete {
		t.Fatalf("lost completion reply cannot be recovered: %+v %v", got, err)
	}
}

func TestUnknownRetainsFenceAfterRestartAtEveryBoundary(t *testing.T) {
	steps := []EventKind{RequestMaintenance, MaintenanceClosed, PreviousDeparted, RequestAPI, APIHealthy, WebHealthy}
	for n := 0; n <= len(steps); n++ {
		t.Run(string(rune('0'+n)), func(t *testing.T) {
			m, r := fixture()
			e := Engine{Store: m}
			op, err := e.Begin(r)
			if err != nil {
				t.Fatal(err)
			}
			for _, k := range steps[:n] {
				op = advance(t, e, op, k)
			}
			op = advance(t, e, op, OutcomeUnknown)
			e = Engine{Store: m}
			got, err := e.Begin(r)
			if err != nil || got.Phase != Held {
				t.Fatalf("original unknown lost: %+v %v", got, err)
			}
			r.ID = "replacement"
			if _, err := e.Begin(r); !errors.Is(err, ErrHeld) {
				t.Fatalf("replacement escaped fence: %v", err)
			}
			if _, err := e.Advance(Event{ID: op.Request.ID, Epoch: 7, From: Held, Kind: RequestAPI}); !errors.Is(err, ErrHeld) {
				t.Fatalf("unknown automatically cleared: %v", err)
			}
			s, _ := m.Load()
			if s.Active != op.Request.ID || s.Current != hash("a") || s.Database != hash("d") {
				t.Fatal("unknown changed prior or DB custody")
			}
		})
	}
}

func TestCommitFailureAndAmbiguousAcknowledgement(t *testing.T) {
	for _, lost := range []bool{false, true} {
		m, r := fixture()
		e := Engine{Store: m}
		m.fail, m.loseReply = !lost, lost
		if _, err := e.Begin(r); err == nil {
			t.Fatal("injected commit error not returned")
		}
		m.fail, m.loseReply = false, false
		op, err := (Engine{Store: m}).Begin(r)
		if err != nil || op.Phase != Prepared {
			t.Fatalf("same-ID inspection/retry failed: %v", err)
		}
		s, _ := m.Load()
		if s.Revision != 1 || len(s.Operations) != 1 {
			t.Fatal("ambiguous begin duplicated durable intent")
		}
		m.loseReply = true
		if _, err := e.Advance(Event{ID: r.ID, Epoch: 7, From: Prepared, Kind: RequestMaintenance}); err == nil {
			t.Fatal("lost transition reply not returned")
		}
		m.loseReply = false
		got, err := (Engine{Store: m}).Begin(r)
		if err != nil || got.Phase != MaintenanceIntent {
			t.Fatal("must inspect original durable phase after ambiguous transition")
		}
		if _, err := e.Advance(Event{ID: r.ID, Epoch: 7, From: Prepared, Kind: RequestMaintenance}); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale transition repeated: %v", err)
		}
	}
}

func TestRefuseChangedBindingsAndUnprovenHealth(t *testing.T) {
	m, r := fixture()
	e := Engine{Store: m}
	for _, mutate := range []func(*Request){
		func(x *Request) { x.Epoch++ },
		func(x *Request) { x.ExpectedPrevious = hash("f") },
		func(x *Request) { x.Database = hash("f") },
		func(x *Request) { x.Release = "not-a-digest" },
		func(x *Request) { x.ID = "../other" },
	} {
		x := r
		mutate(&x)
		if _, err := e.Begin(x); err == nil {
			t.Fatalf("invalid binding accepted: %+v", x)
		}
	}
	op, err := e.Begin(r)
	if err != nil {
		t.Fatal(err)
	}
	x := r
	x.Profile = hash("f")
	if _, err := e.Begin(x); !errors.Is(err, ErrConflict) {
		t.Fatal("same ID accepted different input")
	}
	op = advance(t, e, op, RequestMaintenance)
	before, _ := m.Load()
	for _, event := range []Event{
		{ID: r.ID, Epoch: 8, From: op.Phase, Kind: MaintenanceClosed, Evidence: hash("e")},
		{ID: "another", Epoch: 7, From: op.Phase, Kind: MaintenanceClosed, Evidence: hash("e")},
		{ID: r.ID, Epoch: 7, From: op.Phase, Kind: MaintenanceClosed},
		{ID: r.ID, Epoch: 7, From: op.Phase, Kind: WebHealthy, Evidence: hash("e")},
	} {
		if _, err := e.Advance(event); err == nil {
			t.Fatal("stale, missing-evidence or out-of-order observation accepted")
		}
	}
	after, _ := m.Load()
	if after.Revision != before.Revision {
		t.Fatal("refusal changed custody state")
	}
}

func TestConcurrentAdmissionHasOneWinner(t *testing.T) {
	m, r := fixture()
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, id := range []string{"first", "second"} {
		go func(id string) {
			<-start
			x := r
			x.ID = id
			_, err := (Engine{Store: m}).Begin(x)
			results <- err
		}(id)
	}
	close(start)
	winners := 0
	for range 2 {
		if err := <-results; err == nil {
			winners++
		} else if !errors.Is(err, ErrHeld) && !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	s, _ := m.Load()
	if winners != 1 || len(s.Operations) != 1 || s.Revision != 1 || s.Active == "" {
		t.Fatalf("competing writer admitted: %+v", s)
	}
}

func TestCorruptRetainedBindingsRefuseBeforeAnyCommit(t *testing.T) {
	for _, mutate := range []func(*State){
		func(s *State) { s.Current = hash("f") },
		func(s *State) { s.Database = hash("f") },
		func(s *State) { s.Epoch++ },
		func(s *State) { s.Revision = ^uint64(0) },
		func(s *State) { s.Active = "" },
		func(s *State) { op := s.Operations["update-1"]; op.Phase = Complete; s.Operations["update-1"] = op },
		func(s *State) { op := s.Operations["update-1"]; op.Hash = hash("f"); s.Operations["update-1"] = op },
	} {
		m, r := fixture()
		e := Engine{Store: m}
		if _, err := e.Begin(r); err != nil {
			t.Fatal(err)
		}
		mutate(&m.s)
		rev := m.s.Revision
		if _, err := e.Begin(r); err == nil {
			t.Fatal("corrupt retained custody accepted by retry")
		}
		if _, err := e.Advance(Event{ID: r.ID, Epoch: 7, From: Prepared, Kind: RequestMaintenance}); err == nil {
			t.Fatal("corrupt retained custody accepted by transition")
		}
		if m.s.Revision != rev {
			t.Fatal("corruption refusal attempted a commit")
		}
	}
}

func TestFailedTransitionCommitDoesNotPublishIntent(t *testing.T) {
	m, r := fixture()
	e := Engine{Store: m}
	if _, err := e.Begin(r); err != nil {
		t.Fatal(err)
	}
	m.fail = true
	if _, err := e.Advance(Event{ID: r.ID, Epoch: 7, From: Prepared, Kind: RequestMaintenance}); err == nil {
		t.Fatal("commit failure hidden")
	}
	m.fail = false
	op, err := (Engine{Store: m}).Begin(r)
	if err != nil || op.Phase != Prepared || m.s.Revision != 1 {
		t.Fatal("failed commit exposed a future effect intent")
	}
}

func candidateAt(t *testing.T, e Engine, r Request, phase Phase) Operation {
	t.Helper()
	op, err := e.Begin(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []EventKind{RequestMaintenance, MaintenanceClosed, PreviousDeparted, RequestAPI, APIHealthy, WebHealthy} {
		op = advance(t, e, op, kind)
		if op.Phase == phase {
			return op
		}
	}
	t.Fatalf("unreachable fixture phase %s", phase)
	return Operation{}
}

func TestKnownCandidateFailureRequiresDepartureAndPreviousHealth(t *testing.T) {
	for _, failureAt := range []Phase{APIStartIntent, WebStartIntent, ReopenIntent} {
		t.Run(string(failureAt), func(t *testing.T) {
			m, r := fixture()
			e := Engine{Store: m}
			op := candidateAt(t, e, r, failureAt)
			op = advance(t, e, op, CandidateFailed)
			// Even a known failure cannot skip re-closing public routing.
			if _, err := e.Advance(Event{ID: r.ID, Epoch: r.Epoch, From: op.Phase, Kind: CandidateDeparted, Evidence: hash("e")}); err == nil {
				t.Fatal("candidate departure bypassed maintenance observation")
			}
			op = advance(t, e, op, RollbackMaintenanceClosed)
			if _, err := e.Advance(Event{ID: r.ID, Epoch: r.Epoch, From: op.Phase, Kind: PreviousAPIHealthy, Evidence: hash("e")}); err == nil {
				t.Fatal("previous writer admitted before candidate departure")
			}
			for _, kind := range []EventKind{CandidateDeparted, PreviousAPIHealthy, PreviousWebHealthy, PreviousRouteHealthy} {
				op = advance(t, e, op, kind)
				s, _ := m.Load()
				if s.Database != r.Database || s.Current != r.ExpectedPrevious {
					t.Fatal("rollback changed database identity or restored wrong code")
				}
				if kind != PreviousRouteHealthy && s.Active != r.ID {
					t.Fatal("rollback released fence before previous route healthy")
				}
			}
			got, err := (Engine{Store: m}).Begin(r)
			if err != nil || got.Phase != RolledBack || m.s.Active != "" {
				t.Fatalf("original rollback result not retained: %+v %v", got, err)
			}
		})
	}
}

func TestUnknownDuringRecoveryKeepsFenceAtEveryBoundary(t *testing.T) {
	steps := []EventKind{RollbackMaintenanceClosed, CandidateDeparted, PreviousAPIHealthy, PreviousWebHealthy}
	for n := 0; n <= len(steps); n++ {
		m, r := fixture()
		e := Engine{Store: m}
		op := candidateAt(t, e, r, ReopenIntent)
		op = advance(t, e, op, CandidateFailed)
		for _, kind := range steps[:n] {
			op = advance(t, e, op, kind)
		}
		op = advance(t, e, op, OutcomeUnknown)
		r.ID = "replacement"
		if _, err := (Engine{Store: m}).Begin(r); !errors.Is(err, ErrHeld) {
			t.Fatal("unknown recovery allowed a competing writer")
		}
		if m.s.Active != op.Request.ID || m.s.Current != hash("a") || m.s.Database != hash("d") {
			t.Fatal("unknown recovery lost retained custody")
		}
	}
}

func completedOperation(r Request) Operation {
	op := Operation{Request: r, Hash: r.hash(), Phase: Prepared}
	for _, kind := range []EventKind{RequestMaintenance, MaintenanceClosed, PreviousDeparted, RequestAPI, APIHealthy, WebHealthy, RouteHealthy} {
		v := Event{ID: r.ID, Epoch: r.Epoch, From: op.Phase, Kind: kind}
		if kind != RequestMaintenance && kind != RequestAPI {
			v.Evidence = hash("e")
		}
		op.Phase, _ = transition(op.Phase, kind)
		op.History = append(op.History, v)
	}
	return op
}

func TestBoundedReceiptsRefuseAdmissionWithoutEviction(t *testing.T) {
	m, r := fixture()
	m.s.Operations = make(map[string]Operation)
	for i := range MaxOperations {
		x := r
		x.ID = fmt.Sprintf("retained-%d", i)
		m.s.Operations[x.ID] = completedOperation(x)
	}
	m.s.Current = r.Release
	e := Engine{Store: m}
	x := r
	x.ID = "new"
	x.ExpectedPrevious, x.Release = r.Release, r.ExpectedPrevious
	if _, err := e.Begin(x); !errors.Is(err, ErrCapacity) {
		t.Fatalf("full store admitted new operation: %v", err)
	}
	r.ID = "retained-0"
	if got, err := e.Begin(r); err != nil || got.Phase != Complete {
		t.Fatalf("full store lost original receipt: %+v %v", got, err)
	}
	if len(m.s.Operations) != MaxOperations || m.s.Revision != 0 {
		t.Fatal("capacity refusal evicted or rewrote history")
	}
	x.ID = "over-cap"
	m.s.Operations[x.ID] = completedOperation(x)
	if _, err := e.Begin(r); !errors.Is(err, ErrCapacity) {
		t.Fatalf("oversized store was traversed/accepted: %v", err)
	}
}

func TestEpochBelongsToIdleCustodyOwnerNotTransitions(t *testing.T) {
	m, r := fixture()
	m.s.Operations = map[string]Operation{r.ID: completedOperation(r)}
	m.s.Current = r.Release
	// Simulated administrator-provisioned idle handoff, not an Engine API.
	m.s.Epoch++
	m.s.Revision++
	e := Engine{Store: m}
	if got, err := e.Begin(r); err != nil || got.Phase != Complete {
		t.Fatal("idle handoff lost historical original-ID readback")
	}
	x := r
	x.ID = "after-handoff"
	x.ExpectedPrevious, x.Release = r.Release, r.ExpectedPrevious
	if _, err := e.Begin(x); !errors.Is(err, ErrConflict) {
		t.Fatal("stale epoch admitted new operation")
	}
	x.Epoch++
	if _, err := e.Begin(x); err != nil {
		t.Fatal(err)
	}
	// Epoch rotation while active cannot clear or bypass the retained fence.
	m.s.Epoch++
	if _, err := e.Begin(x); err == nil {
		t.Fatal("active custody epoch was silently replaced")
	}
	if m.s.Active != x.ID {
		t.Fatal("bad custody handoff cleared the active fence")
	}
}
