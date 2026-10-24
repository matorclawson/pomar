package serviceupgrade

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type fakeDriver struct {
	events  []string
	fail    string
	changed bool
	reads   int
	j       Journal
	openErr error
}

func (f *fakeDriver) event(name string) error {
	f.events = append(f.events, name)
	if f.fail == name {
		return errors.New("synthetic failure")
	}
	return nil
}
func (f *fakeDriver) Check(context.Context) error { return f.event("check") }
func (f *fakeDriver) SigningPolicy() string       { return "internal_certificate" }
func (f *fakeDriver) Observe(context.Context) (Observation, error) {
	f.reads++
	if err := f.event("observe"); err != nil {
		return Observation{}, err
	}
	o := Observation{Pin: "baseline", History: "history", KeyID: "key", PID: 123, Birth: "original-birth"}
	if f.changed && f.reads > 1 {
		o.Birth = "reused-pid"
	}
	return o, nil
}
func (f *fakeDriver) Archive(context.Context, Observation) (string, error) {
	return "synthetic-private-archive", f.event("archive")
}
func (f *fakeDriver) Save(j Journal) error                      { f.j = j; return f.event("save:" + j.Phase) }
func (f *fakeDriver) Fence(context.Context) error               { return f.event("fence") }
func (f *fakeDriver) Stop(context.Context, Observation) error   { return f.event("stop") }
func (f *fakeDriver) Replace(context.Context) error             { return f.event("replace") }
func (f *fakeDriver) Start(context.Context) error               { return f.event("start") }
func (f *fakeDriver) Verify(context.Context, Observation) error { return f.event("verify") }
func (f *fakeDriver) Open(context.Context) error {
	if err := f.event("open"); err != nil {
		return err
	}
	return f.openErr
}
func (f *fakeDriver) Restore(context.Context, Journal) error { return f.event("restore") }

func contains(events []string, name string) bool {
	for _, s := range events {
		if s == name {
			return true
		}
	}
	return false
}

func TestCheckDoesNotCreateAnArchiveOrChangeTheService(t *testing.T) {
	f := &fakeDriver{}
	if _, err := Inspect(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.events, []string{"check", "observe"}) {
		t.Fatal(f.events)
	}
}

func TestPIDReuseRefusesStopAndReplacement(t *testing.T) {
	f := &fakeDriver{changed: true}
	j, err := Apply(context.Background(), f, "frozen-manifest")
	if err == nil || j.Phase != "stopping" || contains(f.events, "stop") || contains(f.events, "replace") || contains(f.events, "open") {
		t.Fatalf("unsafe identity transition: %v %v", f.events, err)
	}
}

func TestFailedPostInstallCheckCannotReopenAdmission(t *testing.T) {
	f := &fakeDriver{fail: "verify"}
	j, err := Apply(context.Background(), f, "frozen-manifest")
	if err == nil || j.Phase != "verifying" || contains(f.events, "open") || f.j.Archive == "" {
		t.Fatalf("post-install failure was hidden: %v %v", f.events, err)
	}
}

func TestEveryEffectHasDurableIntentFirst(t *testing.T) {
	f := &fakeDriver{}
	j, err := Apply(context.Background(), f, "frozen-manifest")
	if err != nil || j.Phase != "complete" {
		t.Fatal(j, err)
	}
	for _, pair := range [][2]string{{"fencing", "fence"}, {"stopping", "stop"}, {"installing", "replace"}, {"starting", "start"}, {"verifying", "verify"}, {"opening", "open"}} {
		intent, effect := -1, -1
		for i, event := range f.events {
			if event == "save:"+pair[0] {
				intent = i
			}
			if event == pair[1] {
				effect = i
			}
		}
		if intent < 0 || effect <= intent {
			t.Fatal(pair, f.events)
		}
	}
}

func TestJournalFailureDoesNotPerformItsEffect(t *testing.T) {
	f := &fakeDriver{fail: "save:installing"}
	if _, err := Apply(context.Background(), f, "frozen-manifest"); err == nil || contains(f.events, "replace") || contains(f.events, "open") {
		t.Fatal(f.events, err)
	}
}

func TestRollbackRequiresTheOriginalBindingAndVerifiedBaseline(t *testing.T) {
	j := Journal{Schema: "pomar.service-upgrade-journal/v1", ManifestSHA: "original", Phase: "installing", Archive: "retained-archive", SigningPolicy: "internal_certificate"}
	f := &fakeDriver{}
	if _, err := Rollback(context.Background(), f, j, "different"); err == nil || len(f.events) != 0 {
		t.Fatal(f.events, err)
	}
	f = &fakeDriver{fail: "verify"}
	if _, err := Rollback(context.Background(), f, j, "original"); err == nil || contains(f.events, "open") {
		t.Fatal(f.events, err)
	}
	f = &fakeDriver{}
	got, err := Rollback(context.Background(), f, j, "original")
	if err != nil || got.Phase != "rolled-back" || !contains(f.events, "restore") || !contains(f.events, "open") {
		t.Fatal(got, f.events, err)
	}
}
func TestCompletionJournalFailureReportsThatAdmissionAlreadyOpened(t *testing.T) {
	f := &fakeDriver{fail: "save:complete"}
	j, e := Apply(context.Background(), f, "original")
	if e == nil || j.Phase != "complete" || !contains(f.events, "open") || !strings.Contains(e.Error(), "admission reopened") {
		t.Fatal(j, e, f.events)
	}
}

func TestJournalRetainsSigningPolicyAndRollbackRefusesAnotherPolicy(t *testing.T) {
	f := &fakeDriver{}
	j, err := Apply(context.Background(), f, "original")
	if err != nil || j.SigningPolicy != "internal_certificate" || f.j.SigningPolicy != j.SigningPolicy {
		t.Fatal(j, f.j, err)
	}
	j.SigningPolicy = "development_transition"
	f = &fakeDriver{}
	if _, err := Rollback(context.Background(), f, j, "original"); err == nil || len(f.events) != 0 {
		t.Fatal("rollback policy mismatch allowed effects", f.events, err)
	}
}

func TestApplyReturnsPostOpenCallerFailureAsItsOwnPhase(t *testing.T) {
	f := &fakeDriver{openErr: &OpeningFailure{Journal: Journal{Phase: "opening-caller-failed", Archive: "retained-archive"}, Err: errors.New("opened, caller verification FAILED")}}
	j, err := Apply(context.Background(), f, "original")
	if err == nil || j.Phase != "opening-caller-failed" || !strings.Contains(err.Error(), "caller verification FAILED") || contains(f.events, "restore") {
		t.Fatal(j, f.events, err)
	}
}

// sow: pomar-SOW-87. Interrupt the rollback transaction itself, not only the
// happy-path restore or the shared admission-opening sequence.
func TestRollbackInterruptionsRetainOriginalBindingAndDoNotSkipVerification(t *testing.T) {
	original := Journal{Schema: "pomar.service-upgrade-journal/v1", ManifestSHA: "original", Phase: "installing", Archive: "retained-archive", SigningPolicy: "internal_certificate", Before: Observation{Pin: "baseline", History: "frozen-history", ManagerTableHistory: "frozen-table"}}
	for _, failure := range []string{"save:rolling-back", "fence", "restore", "start", "verify", "save:rollback-opening", "open", "save:rolled-back"} {
		t.Run(failure, func(t *testing.T) {
			f := &fakeDriver{fail: failure}
			interrupted, err := Rollback(context.Background(), f, original, original.ManifestSHA)
			if err == nil || interrupted.Archive != original.Archive || interrupted.Before != original.Before || interrupted.ManifestSHA != original.ManifestSHA {
				t.Fatal("interruption lost the original recovery binding", interrupted, err)
			}
			if failure != "open" && failure != "save:rolled-back" && contains(f.events, "open") {
				t.Fatal("rollback reopened before all recovery checks succeeded", f.events)
			}
			if failure == "save:rolling-back" && (contains(f.events, "fence") || contains(f.events, "restore")) {
				t.Fatal("rollback effect without durable intent", f.events)
			}
			if failure == "save:rolled-back" && !strings.Contains(err.Error(), "baseline admission reopened") {
				t.Fatal("post-open journal failure concealed", err)
			}
			// Repeating explicit rollback must run the restore guard and verify
			// again. A changed-history refusal cannot be skipped on recovery.
			refusing := &fakeDriver{fail: "restore"}
			if _, err := Rollback(context.Background(), refusing, interrupted, original.ManifestSHA); err == nil || contains(refusing.events, "start") || contains(refusing.events, "open") {
				t.Fatal("interrupted rollback bypassed the restore refusal", refusing.events, err)
			}
			resumed := &fakeDriver{}
			if got, err := Rollback(context.Background(), resumed, interrupted, original.ManifestSHA); err != nil || got.Phase != "rolled-back" || !contains(resumed.events, "restore") || !contains(resumed.events, "verify") || !contains(resumed.events, "open") {
				t.Fatal("explicit rollback failed to revalidate and converge", got, resumed.events, err)
			}
		})
	}
}
