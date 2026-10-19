// Package tools holds repository-level tests for the shell tools that
// don't belong to any one internal package. track3_preflight_test.go
// exercises tools/track3-preflight.sh as a real subprocess against
// controlled fixtures, never the live zeocore checkout or a real job.
package tools

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// zeocoreFixture returns a minimal, self-contained directory shaped like
// enough of zeroemployeeorg/zeocore for the preflight script's own reads:
// its pandoc floor (src/zeo_core/integrations/pandoc/_runner.py), its CI
// pin (tools/install-pandoc.sh) and its Python requirement (pyproject.toml).
// Never the real clone -- hermetic and under this test's own control.
func zeocoreFixture(t *testing.T, ciPin string) string {
	t.Helper()
	root := t.TempDir()
	runner := filepath.Join(root, "src", "zeo_core", "integrations", "pandoc", "_runner.py")
	if err := os.MkdirAll(filepath.Dir(runner), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runner, []byte("MIN_PANDOC_VERSION: Final = (2, 15)\n"), 0644); err != nil {
		t.Fatal(err)
	}
	toolsDir := filepath.Join(root, "tools")
	if err := os.MkdirAll(toolsDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(toolsDir, "install-pandoc.sh"), []byte("VERSION=\""+ciPin+"\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pyproject.toml"), []byte("requires-python = \">=3.14\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return root
}

// runPreflight invokes the real script as a subprocess, returning its
// combined output. PATH is passed through so a real pandoc/uv, if present
// on the test host, is actually exercised -- this is a real subprocess
// test, not a reimplementation of the script's own logic.
func runPreflight(t *testing.T, repo, scratch, jobTarget string) (string, error) {
	t.Helper()
	script, err := filepath.Abs("track3-preflight.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", script, repo, scratch, jobTarget)
	cmd.Env = append(os.Environ(), "TZ=UTC")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestTrack3PreflightReportsThreeDistinctPandocValues(t *testing.T) {
	repo := zeocoreFixture(t, "3.1.3")
	out, err := runPreflight(t, repo, t.TempDir(), "3.11")
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
	for _, want := range []string{
		"pandoc floor (code minimum, from " + filepath.Join(repo, "src/zeo_core/integrations/pandoc/_runner.py") + "): 2.15",
		"pandoc CI pin (from " + filepath.Join(repo, "tools/install-pandoc.sh") + "): 3.1.3",
		"pandoc job target (council/Architect operational policy, not a repo fact): 3.11",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

// council's settlement (msg-architect-architect-pandoc-settled-2156): the
// installed pandoc is checked against the JOB TARGET, never the repo's own
// CI pin -- a CI pin lower than the job target must not read as satisfied.
func TestTrack3PreflightChecksInstalledAgainstJobTargetNotCIPin(t *testing.T) {
	if _, err := exec.LookPath("pandoc"); err != nil {
		t.Skip("no pandoc on PATH to exercise the real version check")
	}
	repo := zeocoreFixture(t, "1.0.0") // a CI pin an installed pandoc would trivially satisfy
	out, err := runPreflight(t, repo, t.TempDir(), "999.0.0")
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "pandoc_status: NOT-CONFIGURED") {
		t.Fatalf("an unmeetable job target must not read as satisfied just because the CI pin is low: %s", out)
	}
}

func TestTrack3PreflightScratchAncestry(t *testing.T) {
	repo := zeocoreFixture(t, "3.1.3")

	t.Run("safe: sticky ancestor is accepted even though world-writable", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "sticky")
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, os.ModeSticky|0o777); err != nil {
			t.Fatal(err)
		}
		out, err := runPreflight(t, repo, filepath.Join(dir, "future-leaf"), "3.11")
		if err != nil {
			t.Fatalf("script failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, "scratch_ancestry_status: VERIFIED") {
			t.Fatalf("a sticky, world-writable ancestor (the /tmp pattern) must be accepted: %s", out)
		}
	})

	t.Run("unsafe: world-writable ancestor without the sticky bit is refused", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "world-writable")
		if err := os.Mkdir(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		out, err := runPreflight(t, repo, filepath.Join(dir, "future-leaf"), "3.11")
		if err != nil {
			t.Fatalf("script failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, "scratch_ancestry_status: NOT-CONFIGURED") {
			t.Fatalf("a world-writable, non-sticky ancestor must be refused: %s", out)
		}
	})

	// pomar's review of pr#142: group-writable without the sticky bit (the
	// safe-ancestor predicate examines mode&0022, group OR other) was
	// silently accepted -- only "others" (not "group") was ever checked.
	t.Run("unsafe: group-writable ancestor without the sticky bit is refused (pomar's finding)", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "group-writable")
		if err := os.Mkdir(dir, 0o770); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o770); err != nil {
			t.Fatal(err)
		}
		out, err := runPreflight(t, repo, filepath.Join(dir, "future-leaf"), "3.11")
		if err != nil {
			t.Fatalf("script failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, "scratch_ancestry_status: NOT-CONFIGURED") {
			t.Fatalf("a group-writable, non-sticky ancestor must be refused, not silently accepted: %s", out)
		}
	})

	t.Run("nonexistent leaf still checks the real existing ancestor chain", func(t *testing.T) {
		root := t.TempDir()
		out, err := runPreflight(t, repo, filepath.Join(root, "not-created-yet"), "3.11")
		if err != nil {
			t.Fatalf("script failed: %v\n%s", err, out)
		}
		if !strings.Contains(out, "leaf exists: NO") || !strings.Contains(out, "scratch_ancestry_status: VERIFIED") {
			t.Fatalf("a safe, existing ancestor with a not-yet-created leaf must still verify: %s", out)
		}
	})
}

// pomar's review of pr#142: when stat itself is unavailable or its output
// is unparseable, the permission string must never silently read as safe.
func TestTrack3PreflightFailsClosedWhenStatIsUnavailable(t *testing.T) {
	repo := zeocoreFixture(t, "3.1.3")
	root := t.TempDir()

	fakeBin := filepath.Join(root, "bin")
	if err := os.Mkdir(fakeBin, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeBin, "stat"), []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}

	script, err := filepath.Abs("track3-preflight.sh")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", script, repo, filepath.Join(root, "future-leaf"), "3.11")
	cmd.Env = append([]string{"PATH=" + fakeBin + ":/usr/bin:/bin", "TZ=UTC"}, filteredEnv("PATH", "TZ")...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "scratch_ancestry_status: NOT-CONFIGURED") || !strings.Contains(string(out), "could not read permission metadata") {
		t.Fatalf("a failed stat must fail the ancestor closed, not read VERIFIED: %s", out)
	}
}

// filteredEnv returns the current environment with the given keys removed,
// so a constructed PATH/TZ above is the only source of truth for them.
func filteredEnv(exclude ...string) []string {
	var out []string
	for _, kv := range os.Environ() {
		skip := false
		for _, k := range exclude {
			if strings.HasPrefix(kv, k+"=") {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, kv)
		}
	}
	return out
}

func TestTrack3PreflightRejectsIncompleteArguments(t *testing.T) {
	repo := zeocoreFixture(t, "3.1.3")
	script, err := filepath.Abs("track3-preflight.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{},
		{repo},
		{repo, t.TempDir()}, // missing the job target
	} {
		cmd := exec.Command("sh", append([]string{script}, args...)...)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("args %v: expected a usage refusal, got success: %s", args, out)
		}
		if !strings.Contains(string(out), "usage:") {
			t.Fatalf("args %v: expected a usage message, got: %s", args, out)
		}
	}
}
