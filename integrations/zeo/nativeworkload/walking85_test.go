package nativeworkload

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func testHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type fixture struct {
	p Walking85Profile
	b map[string]any
	c map[string]any
}

func newFixture() fixture {
	p := Walking85Profile{
		SourceRoot: "/source/repo", InputRoot: "/data/original", ScratchRoot: "/attempts/original-1",
		BindingPath: "/owner/profile/binding.json", ClosurePath: "/owner/profile/closure.json",
		Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40), Base: strings.Repeat("c", 40),
		NodePath: "/owner/tools/node", NodeSHA256: strings.Repeat("d", 64), NodeVersion: "v24.19.0",
		GitPath: "/owner/tools/git", GitSHA256: strings.Repeat("e", 64), Mode: "--run",
	}
	files := []filePin{}
	for _, role := range []string{"node", "git", "npm", "npm-package", "vitest-entry", "vitest-package", "sharp-entry", "sharp-package", "sharp-native", "sharp-native-package", "sharp-libvips-package", "sharp-libvips-entry", "sharp-libvips-versions"} {
		pin := filePin{Path: "/owner/tools/" + role, Bytes: 1, SHA256: strings.Repeat("f", 64), Role: role}
		if role == "node" {
			pin.SHA256 = p.NodeSHA256
		}
		if role == "git" {
			pin.SHA256 = p.GitSHA256
		}
		files = append(files, pin)
	}
	return fixture{p: p, c: map[string]any{"files": files}, b: map[string]any{
		"schema":    "walking85-fixed-harness-v1",
		"source":    map[string]any{"commit": p.Commit, "tree": p.Tree, "base": p.Base},
		"toolchain": map[string]any{"platform": "darwin", "arch": "arm64", "nodeVersion": p.NodeVersion},
		// The adapter must preserve the complete binding bytes, not invent
		// replacements for Product's additional validation fields.
		"inputs": map[string]any{"qualification": "synthetic control DATA"},
	}}
}

func (f fixture) encoded(t *testing.T) (Walking85Profile, []byte, []byte) {
	t.Helper()
	closure, err := json.Marshal(f.c)
	if err != nil {
		t.Fatal(err)
	}
	f.b["toolchain"].(map[string]any)["closure"] = filePin{Path: f.p.ClosurePath, Bytes: int64(len(closure)), SHA256: testHash(closure)}
	binding, err := json.Marshal(f.b)
	if err != nil {
		t.Fatal(err)
	}
	p := f.p
	p.BindingSHA256 = testHash(binding)
	return p, binding, closure
}

func TestWalking85FixedInvocationAndNoHostEnvironment(t *testing.T) {
	t.Setenv("NODE_OPTIONS", "--import=/outside/loader.mjs")
	t.Setenv("NODE_PATH", "/outside/modules")
	t.Setenv("PRIVATE_FIXTURE_SECRET", "must-not-inherit")
	for _, mode := range []string{"--run", "--check"} {
		f := newFixture()
		f.p.Mode = mode
		p, b, c := f.encoded(t)
		beforeB, beforeC := string(b), string(c)
		got, err := prepareWalking85("darwin", "arm64", p, b, c)
		if err != nil {
			t.Fatal(err)
		}
		if got.Executable != p.NodePath || got.ExecutableSHA256 != p.NodeSHA256 || !got.StableExecutablePath || got.Directory != p.SourceRoot {
			t.Fatal("installed executable identity or source directory changed", got)
		}
		if !reflect.DeepEqual(got.Args, []string{"/source/repo/qualification/walking85/run.mjs", mode}) || got.OutputRoot != "/attempts/original-1/output" {
			t.Fatal("fixed command/output contract changed", got)
		}
		want := []string{"HOME=/attempts/original-1/home", "TMPDIR=/attempts/original-1/tmp", "PATH=/owner/tools:/owner/tools:/usr/bin:/bin", "LC_ALL=C", "TZ=UTC",
			"DT_WALKING85_BINDING=/owner/profile/binding.json", "DT_WALKING85_INPUT_ROOT=/data/original", "DT_WALKING85_OUTPUT_ROOT=/attempts/original-1/output", "DT_NATIVE_SOURCE_ROOT=/source/repo"}
		if !reflect.DeepEqual(got.Env, want) || string(b) != beforeB || string(c) != beforeC {
			t.Fatal("environment inherited data or input binding bytes were rewritten", got.Env)
		}
	}
}

func TestWalking85RefusesConflictingOwnerAndBindingSelections(t *testing.T) {
	cases := map[string]func(*fixture){
		"arbitrary argv":         func(f *fixture) { f.p.Mode = "--run --extra" },
		"relative source":        func(f *fixture) { f.p.SourceRoot = "source/repo" },
		"root directory":         func(f *fixture) { f.p.ScratchRoot = "/" },
		"traversing source":      func(f *fixture) { f.p.SourceRoot = "/source/../repo" },
		"PATH injection":         func(f *fixture) { f.p.GitPath = "/owner/tools:extra/git" },
		"environment newline":    func(f *fixture) { f.p.InputRoot = "/data\nNODE_OPTIONS=bad" },
		"source DATA overlap":    func(f *fixture) { f.p.InputRoot = f.p.SourceRoot + "/data" },
		"source scratch overlap": func(f *fixture) { f.p.ScratchRoot = f.p.SourceRoot + "/out" },
		"DATA scratch overlap":   func(f *fixture) { f.p.ScratchRoot = f.p.InputRoot + "/out" },
		"writable binding":       func(f *fixture) { f.p.BindingPath = f.p.ScratchRoot + "/binding.json" },
		"writable executable":    func(f *fixture) { f.p.NodePath = f.p.ScratchRoot + "/node" },
		"schema drift":           func(f *fixture) { f.b["schema"] = "other" },
		"source commit drift":    func(f *fixture) { f.b["source"].(map[string]any)["commit"] = strings.Repeat("0", 40) },
		"source tree drift":      func(f *fixture) { f.b["source"].(map[string]any)["tree"] = strings.Repeat("0", 40) },
		"source base drift":      func(f *fixture) { f.b["source"].(map[string]any)["base"] = strings.Repeat("0", 40) },
		"base as candidate":      func(f *fixture) { f.p.Commit = f.p.Base },
		"Linux profile":          func(f *fixture) { f.b["toolchain"].(map[string]any)["platform"] = "linux" },
		"wrong architecture":     func(f *fixture) { f.b["toolchain"].(map[string]any)["arch"] = "x64" },
		"wrong Node version":     func(f *fixture) { f.b["toolchain"].(map[string]any)["nodeVersion"] = "v26.7.0" },
		"relocated Node":         func(f *fixture) { f.p.NodePath = "/private/copy/node" },
		"wrong Node pin":         func(f *fixture) { f.p.NodeSHA256 = strings.Repeat("0", 64) },
		"wrong Git pin":          func(f *fixture) { f.p.GitSHA256 = strings.Repeat("0", 64) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			mutate(&f)
			p, b, c := f.encoded(t)
			got, err := prepareWalking85("darwin", "arm64", p, b, c)
			if err == nil || !reflect.DeepEqual(got, Walking85Invocation{}) {
				t.Fatal("refusal returned a usable invocation", got, err)
			}
		})
	}
}

func TestWalking85RefusesIncompleteOrAmbiguousClosure(t *testing.T) {
	for _, name := range []string{"missing role", "duplicate role", "duplicate path", "traversal", "invalid pin", "zero bytes"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture()
			files := f.c["files"].([]filePin)
			switch name {
			case "missing role":
				files = files[:len(files)-1]
			case "duplicate role":
				files[1].Role = files[0].Role
			case "duplicate path":
				files[1].Path = files[0].Path
			case "traversal":
				files[2].Path = "/owner/../outside/npm"
			case "invalid pin":
				files[2].SHA256 = "bad"
			case "zero bytes":
				files[2].Bytes = 0
			}
			f.c["files"] = files
			p, b, c := f.encoded(t)
			if _, err := prepareWalking85("darwin", "arm64", p, b, c); err == nil {
				t.Fatal("invalid closure accepted")
			}
		})
	}
}

func TestWalking85RefusesChangedRawBytesAndDuplicateJSON(t *testing.T) {
	f := newFixture()
	p, b, c := f.encoded(t)
	if _, err := prepareWalking85("darwin", "arm64", p, append(b, ' '), c); err == nil {
		t.Fatal("changed binding bytes accepted")
	}
	if _, err := prepareWalking85("darwin", "arm64", p, b, append(c, ' ')); err == nil {
		t.Fatal("changed closure bytes accepted")
	}
	for _, raw := range []string{`{"schema":"other","schema":"walking85-fixed-harness-v1"}`, `{}`, `null`, `{} {}`} {
		p.BindingSHA256 = testHash([]byte(raw))
		if _, err := prepareWalking85("darwin", "arm64", p, []byte(raw), c); err == nil {
			t.Fatal("ambiguous/incomplete binding accepted", raw)
		}
	}
	p.BindingSHA256 = testHash(b)
	if _, err := prepareWalking85("linux", "arm64", p, b, c); err == nil {
		t.Fatal("Linux route accepted")
	}
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		if _, err := PrepareWalking85(p, b, c); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWalking85BoundsAndArtifactAliasing(t *testing.T) {
	f := newFixture()
	f.p.GitPath = f.p.BindingPath
	p, b, c := f.encoded(t)
	if _, err := prepareWalking85("darwin", "arm64", p, b, c); err == nil {
		t.Fatal("executable aliases binding file")
	}
	f = newFixture()
	f.b["extra"] = strings.Repeat("x", 1<<20)
	p, b, c = f.encoded(t)
	if _, err := prepareWalking85("darwin", "arm64", p, b, c); err == nil {
		t.Fatal("oversized correctly pinned binding accepted")
	}
	f = newFixture()
	var nested any = "leaf"
	for range 40 {
		nested = []any{nested}
	}
	f.b["extra"] = nested
	p, b, c = f.encoded(t)
	if _, err := prepareWalking85("darwin", "arm64", p, b, c); err == nil {
		t.Fatal("excessive JSON nesting accepted")
	}
}

func TestWalking85GitLookupSelectsThePinnedGit(t *testing.T) {
	f := newFixture()
	root := t.TempDir()
	nodeDir, gitDir := filepath.Join(root, "node-bin"), filepath.Join(root, "git-bin")
	for _, dir := range []string{nodeDir, gitDir} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	f.p.NodePath, f.p.GitPath = filepath.Join(nodeDir, "node"), filepath.Join(gitDir, "git")
	nodeBytes, gitBytes := []byte("synthetic Node control"), []byte("selected Git control")
	f.p.NodeSHA256, f.p.GitSHA256 = testHash(nodeBytes), testHash(gitBytes)
	for path, raw := range map[string][]byte{f.p.NodePath: nodeBytes, f.p.GitPath: gitBytes, filepath.Join(nodeDir, "git"): []byte("shadow Git control")} {
		if err := os.WriteFile(path, raw, 0700); err != nil {
			t.Fatal(err)
		}
	}
	files := f.c["files"].([]filePin)
	files[0].Path, files[0].SHA256, files[0].Bytes = f.p.NodePath, f.p.NodeSHA256, int64(len(nodeBytes))
	files[1].Path, files[1].SHA256, files[1].Bytes = f.p.GitPath, f.p.GitSHA256, int64(len(gitBytes))
	f.c["files"] = files
	p, b, c := f.encoded(t)
	plan, err := prepareWalking85("darwin", "arm64", p, b, c)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range plan.Env {
		if value, ok := strings.CutPrefix(entry, "PATH="); ok {
			t.Setenv("PATH", value)
		}
	}
	// LookPath checks executable selection only; none of these synthetic
	// control files is executed and no native workload is started.
	selected, err := exec.LookPath("git")
	if err != nil || selected != p.GitPath {
		t.Fatalf("selected %q, want pinned Git %q: %v", selected, p.GitPath, err)
	}
	raw, err := os.ReadFile(selected)
	if err != nil || testHash(raw) != p.GitSHA256 {
		t.Fatal("resolved Git bytes differ from owner selection", err)
	}
}

func TestWalking85RefusesGitWithoutTheDriverCommandName(t *testing.T) {
	f := newFixture()
	f.p.GitPath = "/owner/tools/git-custom"
	files := f.c["files"].([]filePin)
	files[1].Path = f.p.GitPath
	f.c["files"] = files
	p, b, c := f.encoded(t)
	if _, err := prepareWalking85("darwin", "arm64", p, b, c); err == nil {
		t.Fatal("owner Git selection cannot be addressed by the fixed driver command git")
	}
}
