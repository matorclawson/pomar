package releaseexecutor

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixtureJournal struct {
	mu sync.Mutex
	record *Record
	saves int
	failSave int
}

func cloneRecord(r Record) Record {
	r.Observation = copyObservation(r.Observation)
	r.Receipts = copyReceipts(r.Receipts)
	return r
}

func (j *fixtureJournal) Reserve(_ context.Context, r Record) (Record, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.record == nil {
		r.Revision = 1
		x := cloneRecord(r)
		j.record = &x
	}
	if j.record.Key != r.Key {
		return Record{}, ErrConflict // also prevents another queued event escaping a hold
	}
	return cloneRecord(*j.record), nil
}

func (j *fixtureJournal) CompareAndSwap(_ context.Context, old uint64, r Record) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.saves++
	if j.saves == j.failSave || j.record.Revision != old || r.Revision != old+1 {
		return ErrDurability
	}
	x := cloneRecord(r)
	j.record = &x
	return nil
}

type fixtureAuthority struct {
	denyConfig bool
	denyReceipt bool
	allowRecovery bool
}

func (a *fixtureAuthority) CheckConfig(context.Context, Config, string) error {
	if a.denyConfig {
		return ErrHeld
	}
	return nil
}

func (a *fixtureAuthority) CheckObservation(_ context.Context, o Observation) error {
	if !bytes.Equal(o.Proof, []byte("verified-main")) && !bytes.Equal(o.Proof, []byte("verified-main-ancestor")) {
		return ErrHeld
	}
	return nil
}

func (a *fixtureAuthority) CheckEffect(context.Context, Config, Effect) error { return nil }
func (a *fixtureAuthority) CheckReceipt(context.Context, Config, Effect, Receipt) error {
	if a.denyReceipt {
		return ErrHeld
	}
	return nil
}
func (a *fixtureAuthority) CheckRecovery(context.Context, Config, Record) error {
	if !a.allowRecovery {
		return ErrHeld
	}
	return nil
}

type fixtureExecutor struct {
	calls []Effect
	results map[string]Receipt
	lose Kind
	reconcileCalls int
}

func receiptFor(e Effect) Receipt {
	r := Receipt{ID: e.ID, Kind: e.Kind, Outcome: "completed", EvidenceSHA256: hashBytes([]byte(e.ID))}
	switch e.Kind {
	case PlanKind:
		r.Plan = Plan{"0.1.0", "engine/v0.1.0", []byte("frozen notes\n"), hashBytes([]byte("frozen notes\n"))}
	case BuildKind:
		r.ArtifactSHA256 = hashBytes([]byte("unsigned artifact"))
	case SignKind:
		r.ArtifactSHA256 = hashBytes([]byte("signed artifact"))
		r.InventorySHA256 = hashBytes([]byte("final inventory"))
		r.VerificationSHA256 = hashBytes([]byte("verified artifact"))
	case EventKind:
		r.SharedEvent = []byte("{\n  \"schema\": \"zeo.release-event/v1\"\n}\n")
		r.SharedEventSHA256 = hashBytes(r.SharedEvent)
		r.ArtifactSHA256 = e.Prior[3].ArtifactSHA256
	case SealKind:
		r.PayloadSHA256 = hashBytes([]byte("canonical payload"))
		r.SignatureSHA256 = hashBytes([]byte("detached signature"))
		r.VerificationSHA256 = hashBytes([]byte("verified payload"))
	}
	return r
}

func (x *fixtureExecutor) Execute(_ context.Context, e Effect) (Receipt, error) {
	x.calls = append(x.calls, e)
	r := receiptFor(e)
	x.results[e.ID] = r
	if x.lose == e.Kind {
		return Receipt{}, errors.New("synthetic lost response after effect")
	}
	return r, nil
}

func (x *fixtureExecutor) Reconcile(_ context.Context, e Effect) (Receipt, error) {
	x.reconcileCalls++
	if r, ok := x.results[e.ID]; ok {
		return r, nil
	}
	return Receipt{ID: e.ID, Kind: e.Kind, Outcome: "unknown"}, nil
}

func fixtureAdapter(t *testing.T) (*Adapter, Observation, *fixtureJournal, *fixtureAuthority, *fixtureExecutor) {
	t.Helper()
	_, raw, pin := fixtureConfig(t)
	j := &fixtureJournal{}
	auth := &fixtureAuthority{}
	x := &fixtureExecutor{results: map[string]Receipt{}}
	a, err := New(raw, pin, j, auth, x, func() time.Time { return time.Unix(1900000000, 0) })
	if err != nil {
		t.Fatal(err)
	}
	o := Observation{"main-move-1", "example/engine", strings.Repeat("b", 40), strings.Repeat("c", 40), []byte("verified-main")}
	return a, o, j, auth, x
}

func TestOriginalCompletesInOrderAndDuplicateDoesNotExecute(t *testing.T) {
	a, o, _, _, x := fixtureAdapter(t)
	var r Record
	for i, kind := range stages {
		var err error
		r, err = a.Step(context.Background(), o)
		if err != nil || r.Next != i+1 || x.calls[i].Kind != kind {
			t.Fatalf("stage %s: %+v %v", kind, r, err)
		}
	}
	if !r.Done {
		t.Fatal("not complete")
	}
	if _, err := a.Step(context.Background(), o); err != nil || len(x.calls) != len(stages) {
		t.Fatal("duplicate did work", err)
	}
	if !bytes.Equal(r.Receipts[4].SharedEvent, receiptFor(x.calls[4]).SharedEvent) {
		t.Fatal("rewrote shared event")
	}
}

func TestLostPlanReplyRecoversSameOriginalWithoutReroll(t *testing.T) {
	a, o, j, auth, x := fixtureAdapter(t)
	x.lose = PlanKind
	if _, err := a.Step(context.Background(), o); !errors.Is(err, ErrHeld) || !j.record.Held {
		t.Fatal("uncertain effect was not held", err)
	}
	if _, err := a.Step(context.Background(), o); !errors.Is(err, ErrHeld) || len(x.calls) != 1 {
		t.Fatal("repeated uncertain effect", err)
	}
	if _, err := a.Reconcile(context.Background(), o); !errors.Is(err, ErrHeld) || x.reconcileCalls != 0 {
		t.Fatal("recovery lacked independent authority", err)
	}
	auth.allowRecovery = true
	r, err := a.Reconcile(context.Background(), o)
	if err != nil || r.Next != 1 || r.Held || len(x.calls) != 1 || r.Receipts[0].Plan.Tag != "engine/v0.1.0" {
		t.Fatal("did not recover frozen original plan", err)
	}
	if _, err := a.Step(context.Background(), o); err != nil || x.calls[1].Kind != TagKind {
		t.Fatal("recovery rerolled version instead of tagging", err)
	}
}

func TestDurableIntentPrecedesEffectsAndLostSaveCannotReplay(t *testing.T) {
	a, o, j, auth, x := fixtureAdapter(t)
	j.failSave = 1
	if _, err := a.Step(context.Background(), o); !errors.Is(err, ErrDurability) || len(x.calls) != 0 {
		t.Fatal("executed without durable intent", err)
	}
	a, o, j, auth, x = fixtureAdapter(t)
	j.failSave = 2 // effect completed, but its completion could not be persisted
	if r, err := a.Step(context.Background(), o); !errors.Is(err, ErrDurability) || r.Done {
		t.Fatal("unconfirmed persistence looked complete", err)
	}
	if _, err := a.Step(context.Background(), o); !errors.Is(err, ErrHeld) || len(x.calls) != 1 {
		t.Fatal("replayed after failed completion write", err)
	}
	auth.allowRecovery = true
	if r, err := a.Reconcile(context.Background(), o); err != nil || r.Next != 1 || len(x.calls) != 1 {
		t.Fatal("failed to reconcile original completion", err)
	}
}

func TestForgedOrChangedMainAndUnverifiedReceiptRefuse(t *testing.T) {
	a, o, _, auth, x := fixtureAdapter(t)
	bad := o
	bad.Proof = []byte("caller says main")
	if _, err := a.Step(context.Background(), bad); err == nil || len(x.calls) != 0 {
		t.Fatal("trusted branch label without provenance")
	}
	o.Proof = []byte("verified-main-ancestor")
	if _, err := a.Step(context.Background(), o); err != nil {
		t.Fatal("refused authenticated delayed main event", err)
	}
	bad = o
	bad.Tree = strings.Repeat("d", 40)
	if _, err := a.Step(context.Background(), bad); !errors.Is(err, ErrConflict) || len(x.calls) != 1 {
		t.Fatal("retargeted original", err)
	}
	auth.denyReceipt = true
	if _, err := a.Step(context.Background(), o); err == nil || len(x.calls) != 1 {
		t.Fatal("used unverified prior receipt")
	}
}

func TestUnknownRecoveryAndOtherEventStayHeld(t *testing.T) {
	a, o, _, auth, x := fixtureAdapter(t)
	x.lose = PlanKind
	_, _ = a.Step(context.Background(), o)
	x.results = map[string]Receipt{}
	auth.allowRecovery = true
	if _, err := a.Reconcile(context.Background(), o); !errors.Is(err, ErrHeld) || len(x.calls) != 1 {
		t.Fatal("unknown recovery caused replay", err)
	}
	o.ID = "later-main-move"
	if _, err := a.Step(context.Background(), o); err == nil || len(x.calls) != 1 {
		t.Fatal("later event escaped suspended original")
	}
}

func TestNoProviderFallbackIncludingTypedNil(t *testing.T) {
	_, raw, pin := fixtureConfig(t)
	var j *fixtureJournal
	if _, err := New(raw, pin, j, &fixtureAuthority{}, &fixtureExecutor{}, time.Now); !errors.Is(err, ErrUnbound) {
		t.Fatal("typed nil journal accepted", err)
	}
}
