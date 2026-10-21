// sow: zeroemployee-SOW-180
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sampleManifest() manifest {
	pin := func(path string) filePin { return filePin{path, strings.Repeat("1", 64), 1} }
	m := manifest{Schema: schema, SourceMode: sourceMode, SourceCommit: creatorHead, SourceTree: strings.Repeat("2", 40), SourceFiles: []filePin{pin("Makefile")}, CacheFiles: []filePin{pin("build-backend/METADATA")}, Tools: []filePin{pin("git"), pin("make"), pin("uv"), pin("node"), pin("python"), pin("sh")}, Limits: limits{8388608, 8388608, 600, 60, 60, 720, 1073741824, 4096}}
	m.ClosureSHA256 = closureDigest(m)
	return m
}

func sampleBytes(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(sampleManifest())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCanonicalManifestAndEscapedCanonicalKey(t *testing.T) {
	b := sampleBytes(t)
	if _, err := parseManifest(b); err != nil {
		t.Fatalf("canonical refused: %v", err)
	}
	b = bytes.Replace(b, []byte(`"source_mode"`), []byte(`"\u0073ource_mode"`), 1)
	if _, err := parseManifest(b); err != nil {
		t.Fatalf("decoded canonical key refused: %v", err)
	}
}

func TestCanonicalKeysAtEveryObject(t *testing.T) {
	for _, tc := range []struct{ name, from, to string }{
		{"Source", `"source_mode"`, `"Source_mode"`},
		{"SOURCE", `"source_mode"`, `"SOURCE_MODE"`},
		{"long-s", `"source_mode"`, `"ſource_mode"`},
		{"duplicate-variant", `"source_mode":`, `"Source_mode":"ignored","source_mode":`},
		{"escaped-duplicate", `"source_mode":`, `"\u0073ource_mode":"ignored","source_mode":`},
		{"exact-duplicate", `"source_mode":`, `"source_mode":"ignored","source_mode":`},
		{"unknown-command", `"source_mode":`, `"command":"anything","source_mode":`},
		{"nested-pin-case", `"sha256"`, `"SHA256"`},
		{"nested-pin-unknown", `"path":`, `"kind":0,"path":`},
		{"nested-pin-duplicate", `"path":`, `"path":"other","path":`},
		{"nested-limits-case", `"stdout_bytes"`, `"STDOUT_BYTES"`},
		{"nested-limits-unknown", `"stdout_bytes":`, `"profile":"other","stdout_bytes":`},
		{"nested-limits-duplicate", `"stdout_bytes":`, `"stdout_bytes":1,"stdout_bytes":`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := bytes.Replace(sampleBytes(t), []byte(tc.from), []byte(tc.to), 1)
			if _, err := parseManifest(b); err == nil {
				t.Fatal("noncanonical or duplicate key accepted")
			}
		})
	}
}

// Exercise the exact-key mechanism against the Council's literal examples,
// without adding a redundant "kind" field to the production manifest schema.
func TestLiteralSourceAndKelvinFoldControls(t *testing.T) {
	objectKeys["fold-control"] = keys("source", "kind")
	defer delete(objectKeys, "fold-control")
	for _, tc := range []struct {
		body    string
		allowed bool
	}{
		{`{"source":"x","kind":"k"}`, true},
		{`{"Source":"x","kind":"k"}`, false},
		{`{"SOURCE":"x","kind":"k"}`, false},
		{`{"ſource":"x","kind":"k"}`, false},
		{`{"source":"x","Source":"y","kind":"k"}`, false},
		{`{"source":"x","Kind":"k"}`, false},
		{`{"sourcex":"x","kind":"k"}`, false},
	} {
		d := json.NewDecoder(strings.NewReader(tc.body))
		d.UseNumber()
		err := exactObject(d, "fold-control")
		if (err == nil) != tc.allowed {
			t.Fatalf("unexpected key verdict for %q: %v", tc.body, err)
		}
	}
}

func TestMalformedNonfiniteTrailingAndSizeRefused(t *testing.T) {
	for _, b := range [][]byte{
		nil, []byte("null"), []byte("[]"), []byte("{"),
		append(sampleBytes(t), []byte(" {}")...),
		bytes.Replace(sampleBytes(t), []byte(`"stdout_bytes":8388608`), []byte(`"stdout_bytes":NaN`), 1),
		bytes.Replace(sampleBytes(t), []byte(`"stdout_bytes":8388608`), []byte(`"stdout_bytes":Infinity`), 1),
		bytes.Replace(sampleBytes(t), []byte(`"stdout_bytes":8388608`), []byte(`"stdout_bytes":1e9999999`), 1),
		bytes.Replace(sampleBytes(t), []byte(`"limits":{`), []byte(`"limits":null,"extra":{`), 1),
		[]byte(strings.Repeat(" ", manifestLimit+1)),
		[]byte(`{"schema":` + strings.Repeat("[", 10000)),
	} {
		if _, err := parseManifest(b); err == nil {
			t.Fatal("invalid JSON or bound accepted")
		}
	}
}

func TestIdentityClosureAndInventoryRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*manifest)
	}{
		{"wrong-head", func(m *manifest) { m.SourceCommit = strings.Repeat("0", 40) }},
		{"wrong-mode", func(m *manifest) { m.SourceMode = "readonly-running-checkout" }},
		{"unbound-closure", func(m *manifest) { m.ClosureSHA256 = strings.Repeat("0", 64) }},
		{"changed-tool", func(m *manifest) { m.Tools[0].SHA256 = strings.Repeat("0", 64) }},
		{"missing-tool", func(m *manifest) { m.Tools = m.Tools[1:] }},
		{"duplicate-tool", func(m *manifest) { m.Tools = append(m.Tools, m.Tools[0]) }},
		{"path-escape", func(m *manifest) { m.CacheFiles[0].Path = "../private" }},
		{"absolute", func(m *manifest) { m.CacheFiles[0].Path = "/private" }},
		{"git-input", func(m *manifest) { m.SourceFiles[0].Path = ".git/config" }},
		{"negative-size", func(m *manifest) { m.CacheFiles[0].Bytes = -1 }},
		{"unbounded-wall", func(m *manifest) { m.Limits.VerifySeconds = 601 }},
		{"whole-too-short", func(m *manifest) { m.Limits.WholeSeconds = 719 }},
		{"unbounded-log", func(m *manifest) { m.Limits.StdoutBytes++ }},
		{"unbounded-files", func(m *manifest) { m.Limits.OutputFiles++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := sampleManifest()
			tc.change(&m)
			b, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseManifest(b); err == nil {
				t.Fatal("invalid binding accepted")
			}
		})
	}
}

func TestInventoryBindsBytesAndRejectsExtraSymlinkAndSpecialOutput(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "input")
	if err := os.WriteFile(path, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pins, err := inventory(ctx, root, 3, 1, false)
	if err != nil || len(pins) != 1 || pins[0].SHA256 != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("wrong inventory: %v", err)
	}
	if err := verifyInventory(ctx, root, pins, false); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("abd"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyInventory(ctx, root, pins, false); err == nil {
		t.Fatal("changed bytes accepted")
	}
	if err := os.WriteFile(filepath.Join(root, "extra"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := outputWithin(ctx, root, 3, 2); err == nil {
		t.Fatal("byte overflow accepted")
	}
	if err := outputWithin(ctx, root, 10, 1); err == nil {
		t.Fatal("file overflow accepted")
	}
	if err := os.Symlink(path, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := inventory(ctx, root, 100, 10, false); err == nil {
		t.Fatal("symlink input accepted")
	}
	if err := outputWithin(ctx, root, 100, 10); err == nil {
		t.Fatal("symlink output accepted")
	}
	if err := noLinks(filepath.Join(root, "link")); err == nil {
		t.Fatal("symlink path accepted")
	}
}

func TestInventoryDeadlineAndAncestorEscape(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := inventory(ctx, root, 100, 10, false); err == nil {
		t.Fatal("expired observation accepted")
	}
	if err := os.Symlink(root, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := noLinks(filepath.Join(root, "alias", "nested")); err == nil {
		t.Fatal("linked ancestor accepted")
	}
	for _, name := range []string{"", ".", "..", "a/../b", "/abs", "../x", "a\\b", ".git/config", "a\x00b"} {
		if relative(name) {
			t.Fatalf("unsafe name %q", name)
		}
	}
}

func TestPinnedCreatorNodeLinkIsLiteralSourceOnly(t *testing.T) {
	root := t.TempDir()
	target := "packages/publication-core/.node-version"
	if err := os.MkdirAll(filepath.Join(root, "packages/publication-core"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, target), []byte("24\n"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, ".node-version")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	pins, err := inventory(context.Background(), root, 1000, 10, true)
	if err != nil || len(pins) != 2 || pins[0].Path != ".node-version" || pins[0].Bytes != int64(len(target)) {
		t.Fatalf("pinned link not bound literally: %v", err)
	}
	if _, err := inventory(context.Background(), root, 1000, 10, false); err == nil {
		t.Fatal("source-only link exception leaked to cache/tool inventory")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../outside", link); err != nil {
		t.Fatal(err)
	}
	if _, err := inventory(context.Background(), root, 1000, 10, true); err == nil {
		t.Fatal("escaped source link accepted")
	}
}

func TestWorkloadCloneRefusesSharedRegularInodes(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "one")
	if err := os.WriteFile(path, []byte("sample"), 0600); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	if err := workloadOwned(context.Background(), root, uid); err != nil {
		t.Fatalf("independent own file refused: %v", err)
	}
	if err := os.Link(path, filepath.Join(root, "two")); err != nil {
		t.Fatal(err)
	}
	if err := workloadOwned(context.Background(), root, uid); err == nil {
		t.Fatal("shared regular inode accepted")
	}
}

type fakeExecutor struct {
	results    []stepResult
	names      []string
	outBudgets []int64
	errBudgets []int64
	deadlines  []time.Duration
}

func (e *fakeExecutor) Step(_ context.Context, name string, duration time.Duration, out, errout int64) stepResult {
	e.names = append(e.names, name)
	e.outBudgets = append(e.outBudgets, out)
	e.errBudgets = append(e.errBudgets, errout)
	e.deadlines = append(e.deadlines, duration)
	r := e.results[0]
	e.results = e.results[1:]
	r.Name = name
	return r
}

func result(exit int, out, errout int64) stepResult {
	return stepResult{Exit: &exit, StdoutBytes: out, StderrBytes: errout, Quiescence: "UNKNOWN"}
}

func TestFixedSequenceAggregateLimitsAndUnknownCleanup(t *testing.T) {
	e := &fakeExecutor{results: []stepResult{result(0, 8, 5), result(0, 2, 3)}}
	l := sampleManifest().Limits
	l.StdoutBytes, l.StderrBytes = 10, 8
	r := sequence(context.Background(), l, e)
	if strings.Join(e.names, ",") != "verify,doctor" {
		t.Fatal("wrong fixed commands")
	}
	if e.outBudgets[1] != 2 || e.errBudgets[1] != 3 {
		t.Fatal("step reset the aggregate limits")
	}
	if e.deadlines[0] != 600*time.Second || e.deadlines[1] != 60*time.Second {
		t.Fatal("wrong deadlines")
	}
	if r.Outcome != "UNKNOWN" || r.Quiescence != "UNKNOWN" || r.Cleanup != "GUEST_TEARDOWN_REQUIRED" || r.Evidence != "SELF_REPORTED" {
		t.Fatal("two zero exits promoted to trusted cleanup/pass")
	}
	if r.SourceMode != "disposable-copy-of-readonly-input" || !strings.Contains(r.Limitations, "transient") || !strings.Contains(r.Limitations, "escaped") {
		t.Fatal("missing report limitations")
	}
}

func TestFailureShortCircuitAndLogOverflowNeverPass(t *testing.T) {
	for _, s := range []stepResult{
		result(2, 1, 1),
		{Name: "verify", Failure: "step_deadline", Quiescence: "UNKNOWN"},
		{Name: "verify", Failure: "start_deadline", Quiescence: "UNKNOWN"},
		{Name: "verify", Failure: "log_limit", Quiescence: "UNKNOWN"},
		{Name: "verify", Failure: "output_limit_or_unknown", Quiescence: "UNKNOWN"},
		result(0, 8388609, 0),
	} {
		e := &fakeExecutor{results: []stepResult{s}}
		r := sequence(context.Background(), sampleManifest().Limits, e)
		if len(e.names) != 1 || r.Outcome != "FAILURE" || r.Quiescence != "UNKNOWN" {
			t.Fatal("failure ran doctor or claimed cleanup/pass")
		}
		if r.Steps[0].Failure != s.Failure {
			t.Fatal("original failure discarded")
		}
	}
}

func TestInheritedDescriptorsAndEscapedDescendantStayUnknown(t *testing.T) {
	// Synthetic observation: the leader exited, while descendant custody is
	// UNKNOWN. Never invoke the real guest runner/UID switching from this test.
	for _, observation := range []string{"inherited-descriptor", "escaped-session", "unconfirmed-group"} {
		t.Run(observation, func(t *testing.T) {
			e := &fakeExecutor{results: []stepResult{result(0, 0, 0), result(0, 0, 0)}}
			r := sequence(context.Background(), sampleManifest().Limits, e)
			if r.Outcome != "UNKNOWN" || r.Quiescence != "UNKNOWN" {
				t.Fatal("unknown descendant custody became clean")
			}
		})
	}
}

func TestWholeDeadlineDoesNotLaunchAnotherStep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := &fakeExecutor{}
	r := sequence(ctx, sampleManifest().Limits, e)
	if len(e.names) != 0 || r.Outcome != "FAILURE" || r.Failure != "whole_deadline" {
		t.Fatal("expired original launched workload")
	}
}
