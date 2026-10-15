//go:build darwin || linux

package providerfence

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const binding = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newStore(t *testing.T, dir, incarnation string, now func() time.Time) *Store {
	t.Helper()
	s, err := Open(dir, "host-one", incarnation, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestLostAcknowledgementAndBinding(t *testing.T) {
	dir := privateDir(t)
	s := newStore(t, dir, "boot-one", time.Now)
	r, err := s.Reserve("job-one", binding, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := s.Reserve(r.ID, binding, 30*time.Second)
	if err != nil || replay != r {
		t.Fatalf("reserve replay changed lease: %#v %v", replay, err)
	}
	_, first, err := s.Start(r.ID, binding, r.Token)
	if err != nil || !first {
		t.Fatalf("first start: %v %v", first, err)
	}
	// Reopen the same incarnation after the response was lost. Do not execute twice.
	reopened := newStore(t, dir, "boot-one", time.Now)
	got, first, err := reopened.Start(r.ID, binding, r.Token)
	if err != nil || first || got.Phase != Starting {
		t.Fatalf("replay: %#v %v %v", got, first, err)
	}
	if _, _, err = reopened.Start(r.ID, strings.Repeat("b", 64), r.Token); err == nil {
		t.Fatal("different payload accepted")
	}
	if _, err = reopened.Abandon(r.ID, binding); err == nil {
		t.Fatal("started identity freed")
	}
}

func TestExpiryNeverReleasesStarted(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	s := newStore(t, privateDir(t), "boot-one", func() time.Time { return now })
	u, _ := s.Reserve("unstarted", binding, time.Second)
	r, _ := s.Reserve("started", binding, time.Second)
	if _, first, err := s.Start(r.ID, binding, r.Token); err != nil || !first {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, first, err := s.Start(u.ID, binding, u.Token); err == nil || first {
		t.Fatal("expired reservation launched")
	}
	got, err := s.Lookup(u.ID)
	if err != nil || got.Phase != Expired || got.Token != "" {
		t.Fatalf("expiry not retained: %#v %v", got, err)
	}
	got, first, err := s.Start(r.ID, binding, r.Token)
	if err != nil || first || got.Phase != Starting {
		t.Fatalf("started custody lost: %#v %v", got, err)
	}
	if _, err := s.Reserve("too-long", binding, 31*time.Second); err == nil {
		t.Fatal("unbounded lease")
	}
}

func TestIncarnationAndUnseenAbandon(t *testing.T) {
	dir := privateDir(t)
	a := newStore(t, dir, "boot-one", time.Now)
	u, _ := a.Reserve("unstarted", binding, time.Second)
	r, _ := a.Reserve("started", binding, time.Second)
	a.Start(r.ID, binding, r.Token)
	b := newStore(t, dir, "boot-two", time.Now)
	if _, err := a.Lookup(r.ID); err == nil {
		t.Fatal("old custodian handle survived")
	}
	if _, err := Open(dir, "host-one", "boot-one", time.Now); err == nil {
		t.Fatal("retired incarnation reused")
	}
	got, _ := b.Lookup(r.ID)
	if got.Phase != Unknown {
		t.Fatal("recovery guessed never-start")
	}
	got, _ = b.Lookup(u.ID)
	if got.Phase != Expired {
		t.Fatal("old reservation survived")
	}
	if _, err := b.Abandon("unseen", binding); err != nil {
		t.Fatal(err)
	}
	got, err := b.Reserve("unseen", binding, time.Second)
	if err != nil || got.Phase != Abandoned {
		t.Fatal("unseen abandon did not fence late reserve")
	}
	if _, _, err := b.Start("unseen", binding, "invented"); err == nil {
		t.Fatal("unseen abandon launched")
	}
}

func TestConcurrentStartVersusAbandon(t *testing.T) {
	for i := 0; i < 12; i++ {
		dir := privateDir(t)
		a := newStore(t, dir, "boot-one", time.Now)
		b := newStore(t, dir, "boot-one", time.Now)
		r, err := a.Reserve("job-one", binding, 30*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var launched atomic.Int32
		for j := 0; j < 8; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, first, _ := a.Start(r.ID, binding, r.Token)
				if first {
					launched.Add(1)
				}
			}()
		}
		wg.Add(1)
		go func() { defer wg.Done(); b.Abandon(r.ID, binding) }()
		wg.Wait()
		got, err := a.Lookup(r.ID)
		if err != nil {
			t.Fatal(err)
		}
		if launched.Load() > 1 || (got.Phase == Abandoned && launched.Load() != 0) || (got.Phase == Starting && launched.Load() != 1) {
			t.Fatalf("unsafe outcome: %s %d", got.Phase, launched.Load())
		}
	}
}

func TestIndependentProcessesStartOnce(t *testing.T) {
	if dir := os.Getenv("POMAR_FENCE_TEST_DIR"); dir != "" {
		s := newStore(t, dir, "boot-one", time.Now)
		r, err := s.Lookup("job-one")
		if err != nil {
			t.Fatal(err)
		}
		_, first, err := s.Start(r.ID, binding, r.Token)
		if err != nil {
			t.Fatal(err)
		}
		if first {
			t.Log("FIRST_START_DECISION")
		}
		return
	}
	dir := privateDir(t)
	s := newStore(t, dir, "boot-one", time.Now)
	if _, err := s.Reserve("job-one", binding, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	cmds := make([]*exec.Cmd, 4)
	for i := range cmds {
		cmds[i] = exec.Command(os.Args[0], "-test.run=^TestIndependentProcessesStartOnce$", "-test.v")
		cmds[i].Env = append(os.Environ(), "POMAR_FENCE_TEST_DIR="+dir)
	}
	var starts atomic.Int32
	var wg sync.WaitGroup
	for _, cmd := range cmds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("child: %v %s", err, b)
			}
			starts.Add(int32(strings.Count(string(b), "FIRST_START_DECISION")))
		}()
	}
	wg.Wait()
	if starts.Load() != 1 {
		t.Fatalf("first decisions=%d", starts.Load())
	}
}

func TestStateCustodyAndMissingStateFailClosed(t *testing.T) {
	for _, name := range []string{"lock", "state.json"} {
		t.Run("symlink-"+name, func(t *testing.T) {
			dir := privateDir(t)
			canary := filepath.Join(privateDir(t), "outside")
			os.WriteFile(canary, []byte("retained"), 0600)
			os.Symlink(canary, filepath.Join(dir, name))
			if s, err := Open(dir, "host-one", "boot-one", time.Now); err == nil {
				s.Close()
				t.Fatal("symlink accepted")
			}
			b, _ := os.ReadFile(canary)
			if string(b) != "retained" {
				t.Fatal("outside file changed")
			}
		})
	}
	dir := privateDir(t)
	s := newStore(t, dir, "boot-one", time.Now)
	s.Abandon("fenced", binding)
	os.Remove(filepath.Join(dir, "state.json"))
	if _, err := s.Reserve("fenced", binding, time.Second); err == nil {
		t.Fatal("state deletion recreated ID")
	}
	if s, err := Open(dir, "host-one", "boot-two", time.Now); err == nil {
		s.Close()
		t.Fatal("reopen erased fences")
	}
}

func TestHardLinksCorruptionAndNamespaceBounds(t *testing.T) {
	for _, name := range []string{"lock", "state.json"} {
		t.Run("hard-link-"+name, func(t *testing.T) {
			dir := privateDir(t)
			canary := filepath.Join(privateDir(t), "outside")
			if err := os.WriteFile(canary, []byte("retained"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(canary, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
			if s, err := Open(dir, "host-one", "boot-one", time.Now); err == nil {
				s.Close()
				t.Fatal("hard link accepted")
			}
			b, _ := os.ReadFile(canary)
			if string(b) != "retained" {
				t.Fatal("outside file changed")
			}
		})
	}
	for _, data := range []string{"not json", `{}`, `{"schema":"future","namespace":"host-one","records":{}}`} {
		dir := privateDir(t)
		s := newStore(t, dir, "boot-one", time.Now)
		if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Lookup("job-one"); err == nil {
			t.Fatal("corrupt state accepted")
		}
	}
	s := newStore(t, privateDir(t), "boot-one", time.Now)
	err := s.transaction(false, func(st *state) error {
		for i := 0; i < maxRecords; i++ {
			id := fmt.Sprintf("fence-%d", i)
			st.Records[id] = Record{ID: id, BindingDigest: binding, Incarnation: "boot-one", Phase: Abandoned}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reserve("additional", binding, time.Second); err == nil {
		t.Fatal("full namespace evicted a fence")
	}
	if got, err := s.Lookup("fence-0"); err != nil || got.Phase != Abandoned {
		t.Fatal("old identity lost")
	}
}
