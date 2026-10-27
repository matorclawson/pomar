package seatterm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func preparedFixture(t *testing.T) (string, Command, []LookupPin) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"stage", "source", "tools"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	program := filepath.Join(root, "source", "program")
	if err := os.WriteFile(program, []byte("#!/bin/sh\nprintf launched > \"$1\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"git", "npm"} {
		if err := os.WriteFile(filepath.Join(root, "tools", name), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	c := Command{Path: program, ExpectedSHA256: sha256OfFile(t, program), UID: -1, GID: -1, Args: []string{filepath.Join(root, "launched")}}
	pins := []LookupPin{lookupFixturePin(t, "node", program), lookupFixturePin(t, "npm", filepath.Join(root, "tools", "npm")), lookupFixturePin(t, "git", filepath.Join(root, "tools", "git"))}
	return root, c, pins
}
func lookupFixturePin(t *testing.T, name, path string) LookupPin {
	t.Helper()
	p, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return LookupPin{Name: name, Path: p, SHA256: hex.EncodeToString(h[:]), Bytes: int64(len(b))}
}
func prepareFixture(t *testing.T, root string, c Command, pins []LookupPin) *PreparedExecutable {
	t.Helper()
	p, err := PrepareExecutable(filepath.Join(root, "stage"), c, []string{"node", "npm", "git"}, pins)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}
func preparedCommand(root string, c Command, p *PreparedExecutable) Command {
	c.Path = p.Path()
	c.PreservesInstallPath = true
	c.Env = []string{"PATH=" + filepath.Join(root, "tools") + ":" + filepath.Dir(p.Path())}
	return c
}
func preparedSpec(c Command, p *PreparedExecutable) SessionSpec {
	return SessionSpec{Name: "prepared", Kind: "agent", Command: c, Prepared: p, Cols: 240, Rows: 24}
}

func TestPreparedChild(t *testing.T) {
	if os.Getenv("POMAR_PREPARED_TEST_CHILD") != "1" {
		return
	}
	p, err := os.Executable()
	if err != nil {
		os.Exit(9)
	}
	fmt.Printf("path-sha=%x\n", sha256.Sum256([]byte(p)))
	os.Exit(0)
}

func TestPreparedFinalExecutablePathAndSessionReplay(t *testing.T) {
	root, c, pins := preparedFixture(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// The program and lookup pins must name the same canonical executable.
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	c.Path = executable
	c.ExpectedSHA256 = sha256OfFile(t, executable)
	c.Args = []string{"-test.run=^TestPreparedChild$"}
	pins[0] = lookupFixturePin(t, "node", executable)
	p := prepareFixture(t, root, c, pins)
	c = preparedCommand(root, c, p)
	c.Env = append(c.Env, "POMAR_PREPARED_TEST_CHILD=1")
	frozenPath := p.Path()
	h, _ := newHost(t)
	spec := preparedSpec(c, p)
	s, created, err := h.Create("prepared-native", "owner", spec)
	if err != nil || !created {
		t.Fatal(created, err)
	}
	select {
	case <-s.done:
	case <-time.After(15 * time.Second):
		t.Fatal("prepared native process did not finish")
	}
	want := fmt.Sprintf("path-sha=%x", sha256.Sum256([]byte(frozenPath)))
	if !strings.Contains(strings.Join(s.Screen().Lines, "\n"), want) || s.cmd.Path != frozenPath || s.exitCode != 0 {
		t.Fatalf("final path/exit mismatch: %s %+v", frozenPath, s.Screen())
	}
	if _, err := os.Lstat(frozenPath); !os.IsNotExist(err) {
		t.Fatalf("prepared executable not cleaned after reap: %v", err)
	}
	again, created, err := h.Create("prepared-native", "owner", spec)
	if err != nil || created || again != s {
		t.Fatal("exact operation replay did not return original", created, err)
	}
	spec.Command.ExpectedSHA256 = strings.Repeat("0", 64)
	if _, _, err := h.Create("prepared-native", "owner", spec); err != ErrOperationConflict {
		t.Fatal("changed prepared pin did not conflict", err)
	}
	if _, _, err := h.Create("new-operation", "owner", preparedSpec(c, p)); err == nil {
		t.Fatal("prepared identity started a second process")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPreparedLookupPolicyRefusesBeforeExecution(t *testing.T) {
	for _, name := range []string{"node-shadow", "npm-shadow", "changed-git", "missing-PATH", "duplicate-PATH", "empty-PATH-entry", "relative-PATH", "changed-pin", "changed-final-path"} {
		t.Run(name, func(t *testing.T) {
			root, c, pins := preparedFixture(t)
			p := prepareFixture(t, root, c, pins)
			c = preparedCommand(root, c, p)
			switch name {
			case "node-shadow", "npm-shadow":
				tool := strings.TrimSuffix(name, "-shadow")
				if err := os.WriteFile(filepath.Join(root, "tools", tool), []byte("#!/bin/sh\necho shadow\n"), 0700); err != nil {
					t.Fatal(err)
				}
			case "changed-git":
				if err := os.WriteFile(filepath.Join(root, "tools", "git"), []byte("#!/bin/sh\necho changed\n"), 0700); err != nil {
					t.Fatal(err)
				}
			case "missing-PATH":
				c.Env = nil
			case "duplicate-PATH":
				c.Env = append(c.Env, c.Env[0])
			case "empty-PATH-entry":
				c.Env[0] += ":"
			case "relative-PATH":
				c.Env = []string{"PATH=.:" + filepath.Dir(p.Path())}
			case "changed-pin":
				c.ExpectedSHA256 = ""
			case "changed-final-path":
				c.Path = pins[0].Path
			}
			h, _ := newHost(t)
			if _, _, err := h.Create("refuse", "owner", preparedSpec(c, p)); err == nil {
				t.Fatal("unsafe preparation launched")
			}
			if _, err := os.Lstat(filepath.Join(root, "launched")); !os.IsNotExist(err) {
				t.Fatal("refused program executed", err)
			}
		})
	}
}

func TestPreparedSingleUseSharedAcrossCopiesAndConcurrentClaims(t *testing.T) {
	root, c, pins := preparedFixture(t)
	p := prepareFixture(t, root, c, pins)
	c = preparedCommand(root, c, p)
	copyOfHandle := *p
	var wins atomic.Int32
	var wg sync.WaitGroup
	finish := make(chan func() error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, e := copyOfHandle.consume(c)
			if e == nil {
				wins.Add(1)
				finish <- f
			}
		}()
	}
	wg.Wait()
	close(finish)
	if wins.Load() != 1 {
		t.Fatalf("%d claims succeeded", wins.Load())
	}
	if err := p.Close(); err == nil {
		t.Fatal("Close removed a consumed live executable")
	}
	for f := range finish {
		if err := f(); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPreparedPolicyCopiesAndCanonicalSymlinkLookup(t *testing.T) {
	root, c, pins := preparedFixture(t)
	realNpm := filepath.Join(root, "source", "npm-cli")
	if err := os.Rename(pins[1].Path, realNpm); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realNpm, pins[1].Path); err != nil {
		t.Fatal(err)
	}
	pins[1] = lookupFixturePin(t, "npm", realNpm)
	p := prepareFixture(t, root, c, pins)
	c = preparedCommand(root, c, p)
	pins[0].SHA256 = "changed"
	view := p.Lookups()
	view[0].Path = "changed"
	oldPATH := os.Getenv("PATH")
	finish, err := p.consume(c)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("PATH") != oldPATH {
		t.Fatal("lookup verification changed global PATH")
	}
	if err := finish(); err != nil {
		t.Fatal(err)
	}
}

func TestPreparedRefusesReplacedInodeAndKeepsForeignOccupant(t *testing.T) {
	root, c, pins := preparedFixture(t)
	p := prepareFixture(t, root, c, pins)
	c = preparedCommand(root, c, p)
	original, err := os.ReadFile(p.Path())
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(root, "replacement")
	if err := os.WriteFile(replacement, original, 0500); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, p.Path()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.consume(c); err == nil {
		t.Fatal("same-byte replacement was accepted")
	}
	if got, err := os.ReadFile(p.Path()); err != nil || string(got) != string(original) {
		t.Fatal("cleanup deleted replacement occupant", err)
	}
	if err := p.Close(); err == nil {
		t.Fatal("uncertain cleanup was reported clean")
	}
}

func TestPreparedStartFailureCleansAndCannotRetry(t *testing.T) {
	root, c, pins := preparedFixture(t)
	if err := os.WriteFile(c.Path, []byte("#!/definitely-missing-pomar-interpreter\n"), 0700); err != nil {
		t.Fatal(err)
	}
	c.ExpectedSHA256 = sha256OfFile(t, c.Path)
	pins[0] = lookupFixturePin(t, "node", c.Path)
	p := prepareFixture(t, root, c, pins)
	c = preparedCommand(root, c, p)
	h, _ := newHost(t)
	if _, _, err := h.Create("exec-failure", "owner", preparedSpec(c, p)); err == nil {
		t.Fatal("missing interpreter ran")
	}
	if _, err := os.Lstat(p.Path()); !os.IsNotExist(err) {
		t.Fatal("failed-start preparation leaked", err)
	}
	if _, _, err := h.Create("exec-failure", "owner", preparedSpec(c, p)); err == nil {
		t.Fatal("failed-start token reused")
	}
}

func TestPreparedRequiresCompleteOwnerPolicyAndCannotBeForgedByJSON(t *testing.T) {
	root, c, pins := preparedFixture(t)
	if _, err := PrepareExecutable(filepath.Join(root, "stage"), c, []string{"node", "npm", "git"}, pins[:2]); err == nil {
		t.Fatal("missing required role accepted")
	}
	blank := c
	blank.ExpectedSHA256 = ""
	if _, err := PrepareExecutable(filepath.Join(root, "stage"), blank, []string{"node", "npm", "git"}, pins); err == nil {
		t.Fatal("unpinned preparation accepted")
	}
	preserve := c
	preserve.PreservesInstallPath = true
	if _, err := PrepareExecutable(filepath.Join(root, "stage"), preserve, []string{"node", "npm", "git"}, pins); err == nil {
		t.Fatal("original install-path requirement was relocated")
	}
	bad := append([]LookupPin(nil), pins...)
	bad[0].SHA256 = strings.Repeat("0", 64)
	if _, err := PrepareExecutable(filepath.Join(root, "stage"), c, []string{"node", "npm", "git"}, bad); err == nil {
		t.Fatal("wrong selected pin accepted")
	}
	p := prepareFixture(t, root, c, pins)
	b, err := json.Marshal(preparedSpec(c, p))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), p.Path()) {
		t.Fatal("opaque prepared identity leaked into JSON")
	}
	var spec SessionSpec
	if err := json.Unmarshal([]byte(`{"Prepared":{}}`), &spec); err != nil || spec.Prepared != nil {
		t.Fatal("JSON constructed prepared authority", err)
	}
	h, _ := newHost(t)
	if _, _, err := h.Create("forged", "owner", preparedSpec(c, &PreparedExecutable{})); err == nil {
		t.Fatal("zero-value prepared handle bypassed pinning")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.consume(preparedCommand(root, c, p)); err == nil {
		t.Fatal("abandoned preparation reused")
	}
}

func TestPreparedCreateFreezesArgumentsAndEnvironmentBeforeAudit(t *testing.T) {
	root, c, pins := preparedFixture(t)
	p := prepareFixture(t, root, c, pins)
	c = preparedCommand(root, c, p)
	unexpected := filepath.Join(root, "unexpected")
	h := NewSessionHost(func(r AuditRecord) error {
		if r.Action == "create" && r.Phase == "intent" {
			c.Env[0] = "PATH=."
			c.Args[0] = unexpected
		}
		return nil
	})
	s, _, err := h.Create("frozen-invocation", "owner", preparedSpec(c, p))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.done:
	case <-time.After(10 * time.Second):
		t.Fatal("frozen invocation did not finish")
	}
	if _, err := os.Stat(filepath.Join(root, "launched")); err != nil {
		t.Fatal("original arguments were changed", err)
	}
	if _, err := os.Stat(unexpected); !os.IsNotExist(err) {
		t.Fatal("caller alias changed executed arguments", err)
	}
}
