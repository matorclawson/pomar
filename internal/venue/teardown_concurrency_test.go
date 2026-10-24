package venue

// sow: pomar-SOW-87. Pause the real deletion boundary, not a manager wrapper.
import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSlowTeardownAllowsUnrelatedLedgerWorkButReservesOriginalPath(t *testing.T) {
	v := openTemp(t)
	if err := v.Intent(KindVM, ClassAttempt, "slow", "store/containers/slow", ""); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(v.Root(), "store/containers/slow"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := v.Created(KindVM, "slow"); err != nil {
		t.Fatal(err)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- v.teardownNoteWith(KindVM, "slow", "fixture", func(path string) error { close(entered); <-release; return os.RemoveAll(path) })
	}()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("remover not entered")
	}
	observed := make(chan error, 1)
	go func() { v.OpenObjects(); observed <- v.Intent(KindVolume, ClassCache, "other", "volumes/other", "") }()
	select {
	case err := <-observed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("slow removal holds venue lock")
	}
	for _, path := range []string{"store/containers/slow", "store/containers/slow/child", "store/containers"} {
		if err := v.Intent(KindVolume, ClassCache, "alias", path, ""); err == nil {
			t.Fatal("overlapping path admitted during deletion", path)
		}
	}
	if err := v.Created(KindVM, "slow"); err == nil {
		t.Fatal("original mutated during removal")
	}
	if err := v.Teardown(KindVM, "slow"); err == nil {
		t.Fatal("duplicate remover entered")
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("remover did not finish")
	}
	if v.IsOpen(KindVM, "slow") {
		t.Fatal("removal not recorded")
	}
	if err := v.Intent(KindVM, ClassAttempt, "slow", "store/containers/slow", ""); err != nil {
		t.Fatal("completed reservation not released", err)
	}
}
