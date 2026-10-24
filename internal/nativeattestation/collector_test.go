package nativeattestation

// sow: pomar-SOW-90. This private fake models journal/observer contracts. It
// proves no production trust, process observation, job admission or cleanup.
import (
	"bytes"
	"context"
	"errors"
	"testing"

	"time"
)

type fixtureObserver struct {
	want                      Original
	policyID                  string
	observed                  observation
	checks, observes, freezes int
	denyAt                    int
	cancelAt                  int
	cancel                    context.CancelFunc
	observeErr                error
	freezeErr                 error
	cancelObserve             bool
	cancelFreeze              bool
	retained                  []byte
	returnConflict            bool
}

func (f *fixtureObserver) CheckOriginal(_ context.Context, original Original, policyID string) error {
	f.checks++
	if f.checks == f.cancelAt && f.cancel != nil {
		f.cancel()
	}
	if !same(original, f.want) || policyID != f.policyID || f.checks == f.denyAt {
		return errors.New("fixture original revoked or foreign")
	}
	return nil
}

func (f *fixtureObserver) Observe(context.Context, Original) (observation, error) {
	f.observes++
	if f.cancelObserve {
		f.cancel()
	}
	return f.observed, f.observeErr
}

func (f *fixtureObserver) Freeze(_ context.Context, original Original, doc []byte) ([]byte, error) {
	f.freezes++
	if !same(original, f.want) {
		return nil, errors.New("fixture foreign original")
	}
	if f.freezeErr != nil {
		return nil, f.freezeErr
	}
	if len(f.retained) != 0 && !bytes.Equal(f.retained, doc) {
		return nil, errors.New("fixture original conflict")
	}
	f.retained = bytes.Clone(doc)
	if f.cancelFreeze {
		f.cancel()
	}
	if f.returnConflict {
		return []byte("different journal bytes"), nil
	}
	return bytes.Clone(f.retained), nil
}

func collectorFixture(t *testing.T) (*Collector, *fixtureObserver, Original, time.Time, context.Context, context.CancelFunc) {
	t.Helper()
	policy, original, observed, now, _ := fixture(t)
	c, err := NewCollector(policy)
	if err != nil {
		t.Fatal(err)
	}
	id, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	f := &fixtureObserver{want: original, policyID: id, observed: observed}
	// Same-package fixture only; the public constructor cannot do this.
	c.observer = f
	ctx, cancel := context.WithDeadline(context.Background(), original.Deadline)
	f.cancel = cancel
	return c, f, original, now, ctx, cancel
}

func TestPublicCollectorUnavailableEvenWithValidImportedProof(t *testing.T) {
	policy, original, observed, now, _ := fixture(t)
	if _, err := Canonical(observed.proof); err != nil {
		t.Fatal(err)
	}
	c, err := NewCollector(policy)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), original.Deadline)
	defer cancel()
	got, err := c.Collect(ctx, original, now)
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, ErrHeld) || len(got.Bytes()) != 0 {
		t.Fatal("uninstalled/imported observer produced evidence", err)
	}
	var absent *Collector
	if _, err := absent.Collect(ctx, original, now); !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil collector accepted", err)
	}
}

func TestCollectorFreezesCompleteBytesAndRecoversOnlySameOriginal(t *testing.T) {
	c, f, original, now, ctx, cancel := collectorFixture(t)
	defer cancel()
	first, err := c.Collect(ctx, original, now)
	if err != nil || f.checks != 3 || f.observes != 1 || f.freezes != 1 {
		t.Fatal("complete observation refused", err, f.checks, f.observes, f.freezes)
	}
	copyOut := first.Bytes()
	copyOut[0] ^= 1
	if bytes.Equal(copyOut, first.Bytes()) {
		t.Fatal("caller changed frozen proof")
	}
	again, err := c.Collect(ctx, original, now)
	if err != nil || !bytes.Equal(again.Bytes(), first.Bytes()) {
		t.Fatal("same-original frozen replay changed", err)
	}
	// No execution method exists on this fake or the production observer port.
	f.observed.proof.Lifecycle.PID++
	if got, err := c.Collect(ctx, original, now); !errors.Is(err, ErrHeld) || len(got.Bytes()) != 0 || !bytes.Equal(f.retained, first.Bytes()) {
		t.Fatal("conflicting original overwrote frozen journal", err)
	}
}

func TestCollectorRejectsPartialRawEvidenceBeforeJournalFreeze(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*fixtureObserver)
	}{
		{"log-truncated", func(f *fixtureObserver) { f.observed.stdout = f.observed.stdout[:1] }},
		{"log-mutated", func(f *fixtureObserver) { f.observed.stdout[0] ^= 1 }},
		{"output-mutated", func(f *fixtureObserver) { f.observed.artifacts["release.json.gz"][0] ^= 1 }},
		{"output-missing", func(f *fixtureObserver) { delete(f.observed.artifacts, "release.json.gz") }},
		{"extra-output", func(f *fixtureObserver) { f.observed.artifacts["foreign"] = []byte("foreign") }},
		{"unknown-cleanup", func(f *fixtureObserver) { f.observed.proof.Lifecycle.CleanupComplete = false }},
		{"native-end-missing", func(f *fixtureObserver) { f.observed.proof.Lifecycle.NativeEnd = time.Time{} }},
		{"failed-wait", func(f *fixtureObserver) { f.observed.proof.Lifecycle.Waited = false }},
		{"imported-original", func(f *fixtureObserver) { f.observed.proof.Original.ID = "imported" }},
		{"observer-unknown", func(f *fixtureObserver) { f.observeErr = errors.New("fixture incomplete observation") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, f, original, now, ctx, cancel := collectorFixture(t)
			defer cancel()
			tc.change(f)
			got, err := c.Collect(ctx, original, now)
			if !errors.Is(err, ErrHeld) || len(got.Bytes()) != 0 || f.freezes != 0 {
				t.Fatal("incomplete/changed observation froze or returned ready", err, f.freezes)
			}
		})
	}
}

func TestCollectorCancellationAndRevocationNeverReleaseOriginal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(*fixtureObserver)
		frozen bool
	}{
		{"first-check-revoked", func(f *fixtureObserver) { f.denyAt = 1 }, false},
		{"last-prefreeze-check-revoked", func(f *fixtureObserver) { f.denyAt = 2 }, false},
		{"postfreeze-check-revoked", func(f *fixtureObserver) { f.denyAt = 3 }, true},
		{"callback-cancelled", func(f *fixtureObserver) { f.cancelAt = 2 }, false},
		{"observe-cancelled", func(f *fixtureObserver) { f.cancelObserve = true }, false},
		{"freeze-cancelled", func(f *fixtureObserver) { f.cancelFreeze = true }, true},
		{"postfreeze-cancelled", func(f *fixtureObserver) { f.cancelAt = 3 }, true},
		{"persistence-unknown", func(f *fixtureObserver) { f.freezeErr = errors.New("fixture persistence unknown") }, false},
		{"journal-returns-conflict", func(f *fixtureObserver) { f.returnConflict = true }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, f, original, now, ctx, cancel := collectorFixture(t)
			defer cancel()
			tc.setup(f)
			got, err := c.Collect(ctx, original, now)
			if !errors.Is(err, ErrHeld) || len(got.Bytes()) != 0 || (len(f.retained) != 0) != tc.frozen {
				t.Fatal("uncertain original returned proof or lost retained bytes", err, len(f.retained))
			}
		})
	}
}

func TestCollectorRefusesInvalidOriginalAndUnboundedContextBeforeObservation(t *testing.T) {
	c, f, original, now, ctx, cancel := collectorFixture(t)
	defer cancel()
	for _, bad := range []context.Context{context.Background(), nil} {
		if _, err := c.Collect(bad, original, now); !errors.Is(err, ErrHeld) || f.checks != 0 || f.observes != 0 {
			t.Fatal("unbounded context reached observer", err)
		}
	}
	late, stop := context.WithDeadline(context.Background(), original.Deadline.Add(time.Second))
	defer stop()
	if _, err := c.Collect(late, original, now); !errors.Is(err, ErrHeld) || f.checks != 0 {
		t.Fatal("larger context deadline accepted", err)
	}
	foreign := original
	foreign.CallerUID++
	if _, err := c.Collect(ctx, foreign, now); !errors.Is(err, ErrHeld) || f.checks != 0 {
		t.Fatal("foreign principal reached observation", err)
	}
	if _, err := c.Collect(ctx, original, original.Deadline); !errors.Is(err, ErrHeld) || f.checks != 0 {
		t.Fatal("expired original reached observation", err)
	}
	cancel()
	if _, err := c.Collect(ctx, original, now); !errors.Is(err, context.Canceled) || f.checks != 0 {
		t.Fatal("cancelled original reached observer", err)
	}
}

func TestCollectorFreezesIndependentPolicyCopy(t *testing.T) {
	policy, original, observed, now, _ := fixture(t)
	c, err := NewCollector(policy)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := policy.Digest()
	policy.Argv[2] = "deploy"
	policy.Tools[0].SHA256 = "changed"
	policy.Inputs[0].Name = "changed"
	policy.Outputs[0].Name = "changed"
	c.observer = &fixtureObserver{want: original, policyID: id, observed: observed}
	ctx, cancel := context.WithDeadline(context.Background(), original.Deadline)
	defer cancel()
	if _, err := c.Collect(ctx, original, now); err != nil {
		t.Fatal("caller mutated retained owner policy", err)
	}
}
