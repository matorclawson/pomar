package serviceupgrade

// sow: pomar-SOW-87. Faults exercise the production opening sequence.
import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestOpeningRedrainsAfterRestartAtEveryBoundary(t *testing.T) {
	for _, crash := range []string{"draining", "exposing", "releasing", "caller-verifying"} {
		t.Run(crash, func(t *testing.T) {
			drained, exposed := false, false // restarted manager is undrained
			phase := "opening"
			fault := true
			save := func(p string) error {
				if fault && p == crash {
					return errors.New("interrupted before persistence")
				}
				phase = p
				return nil
			}
			drain := func(on bool) error {
				if on && phase != "draining" {
					t.Fatal("drain lacks durable intent")
				}
				if !on && (phase != "releasing" || !exposed) {
					t.Fatal("release out of order")
				}
				drained = on
				return nil
			}
			expose := func() error {
				if !drained || phase != "exposing" {
					t.Fatal("directory opened before drain and persisted intent")
				}
				exposed = true
				return nil
			}
			caller := func() error {
				if drained || !exposed || phase != "caller-verifying" {
					t.Fatal("caller verification is not post-open")
				}
				return nil
			}
			if err := reopenAdmission(context.Background(), save, drain, expose, caller); err == nil {
				t.Fatal("fault not reached")
			}
			// A process restart erases drain, not the persisted opening journal.
			drained = false
			fault = false
			if err := reopenAdmission(context.Background(), save, drain, expose, caller); err != nil {
				t.Fatal(err)
			}
			if phase != "caller-verified" || drained || !exposed {
				t.Fatal("opening did not converge", phase)
			}
		})
	}
}

func TestOpeningIntentFailureDoesNotExposeOrRelease(t *testing.T) {
	for _, fail := range []string{"draining", "exposing"} {
		t.Run(fail, func(t *testing.T) {
			exposed, released := false, false
			err := reopenAdmission(context.Background(), func(s string) error {
				if s == fail {
					return errors.New("fsync failed")
				}
				return nil
			}, func(on bool) error { released = !on; return nil }, func() error { exposed = true; return nil }, func() error { t.Fatal("caller reached"); return nil })
			if err == nil || exposed || released {
				t.Fatal("effect after failed intent", err)
			}
		})
	}
}

func TestPostOpenCallerFailureIsReportedWithoutRollback(t *testing.T) {
	phase := ""
	opened := false
	err := reopenAdmission(context.Background(), func(s string) error { phase = s; return nil }, func(bool) error { return nil }, func() error { opened = true; return nil }, func() error { return errors.New("caller transport lost") })
	if err == nil || !opened || phase != "caller-failed" || !strings.Contains(err.Error(), "opened, caller verification FAILED") || !strings.Contains(err.Error(), "no automatic rollback") {
		t.Fatal(phase, opened, err)
	}
}

func TestResumeOpeningCannotReinterpretAnotherTransactionPhase(t *testing.T) {
	for _, phase := range []string{"opening", "opening-exposing", "opening-caller-failed", "rollback-opening", "rollback-opening-releasing"} {
		if !openingPhase(phase) {
			t.Fatal("valid opening refused", phase)
		}
	}
	for _, phase := range []string{"", "prepared", "installing", "starting", "complete", "rolled-back", "opening-forged"} {
		if openingPhase(phase) {
			t.Fatal("unrelated operation accepted", phase)
		}
	}
}

func TestOwnerOnlyVerificationRetainsEveryIdentityBinding(t *testing.T) {
	before := Observation{Pin: "old", History: "history", ManagerTableHistory: "table", KeyID: "key", Capacity: "both", OwnerCapacity: "owner", CallerCapacity: "caller", CallerHistory: "caller-history"}
	after := before
	after.Pin = "new"
	if err := preservedObservation(after, before, "new"); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"table", "history", "key", "both", "owner", "caller", "caller-history"} {
		changed := after
		switch field {
		case "table":
			changed.ManagerTableHistory = "changed"
		case "history":
			changed.History = "changed"
		case "key":
			changed.KeyID = "changed"
		case "both":
			changed.Capacity = "changed"
		case "owner":
			changed.OwnerCapacity = "changed"
		case "caller":
			changed.CallerCapacity = "changed"
		case "caller-history":
			changed.CallerHistory = "changed"
		}
		if preservedObservation(changed, before, "new") == nil {
			t.Fatal("binding lost", field)
		}
	}
}
