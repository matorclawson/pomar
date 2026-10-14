package codexseat

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/zeroemployeeorg/pomar/internal/agentenv"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func fixture(t *testing.T) Supervisor {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	state := filepath.Join(root, "state")
	for _, p := range []string{home, state} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	network := true
	return Supervisor{Launch: &agentenv.SeatLaunch{Sandbox: "workspace-write", Approvals: "on-request", NetworkAccess: &network, Model: "fixture-model", Effort: "high", CWD: "/work"}, Seat: "example", Home: home, StateDir: state, Workspace: "/work", Binary: "/opt/codex", In: strings.NewReader(""), Out: &bytes.Buffer{}}
}
func pending(s Supervisor) record {
	return record{Seat: s.Seat, ConfigurationSHA256: s.configurationDigest(), Schema: "pomar.codex-seat-thread/v1", State: "starting", Before: []string{}, Workspace: s.Workspace, BinarySHA256: LinuxExecutableSHA256, Version: Version}
}
func rollout(t *testing.T, s Supervisor, name, id, source string) string {
	t.Helper()
	dir := filepath.Join(s.Home, "sessions")
	os.MkdirAll(dir, 0700)
	p := filepath.Join(dir, name+".jsonl")
	b, _ := json.Marshal(map[string]any{"type": "session_meta", "payload": map[string]any{"id": id, "cwd": s.Workspace, "source": source}})
	if err := os.WriteFile(p, append(b, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

const id1 = "01a101bc-0986-79e1-b3bd-b3bbc2a05da2"
const id2 = "01a101bc-0986-79e1-b3bd-b3bbc2a05da3"

func TestBindOneRootAndResumeExactID(t *testing.T) {
	s := fixture(t)
	old := rollout(t, s, "old", id2, "cli")
	r := pending(s)
	r.Before = []string{old}
	rollout(t, s, "new", id1, "cli")
	got, err := s.bind(r)
	if err != nil || got.Thread != id1 || got.State != "bound" {
		t.Fatalf("bind %+v %v", got, err)
	}
	restored, err := s.read()
	if err != nil || restored.Thread != id1 {
		t.Fatalf("restore %+v %v", restored, err)
	}
	args := s.Args(restored.Thread)
	if len(args) < 2 || args[0] != "resume" || args[1] != id1 {
		t.Fatalf("not exact resume %q", args)
	}
	for _, bad := range []string{"--last", "--session-id", "--dangerously-bypass-approvals-and-sandbox"} {
		if slices.Contains(args, bad) {
			t.Fatal("unsafe/wrong provider resume", args)
		}
	}
}
func TestAmbiguousOrMissingIdentityRemainsHeld(t *testing.T) {
	for _, n := range []int{0, 2} {
		t.Run(string(rune('0'+n)), func(t *testing.T) {
			s := fixture(t)
			r := pending(s)
			s.write(r)
			if n == 2 {
				rollout(t, s, "one", id1, "cli")
				rollout(t, s, "two", id2, "cli")
			}
			for i := 0; i < 2; i++ {
				if _, err := s.bind(r); !errors.Is(err, ErrHeld) {
					t.Fatal("ambiguous identity accepted", err)
				}
			}
			stored, _ := s.read()
			if stored.State != "starting" || stored.Thread != "" {
				t.Fatalf("ambiguity became binding %+v", stored)
			}
		})
	}
}
func TestIgnoresSubagentIdentityAndNeverReadsTranscript(t *testing.T) {
	s := fixture(t)
	rollout(t, s, "child", id2, "subagent")
	p := rollout(t, s, "root", id1, "cli")
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("private transcript is not JSON and must never be parsed\n")
	f.Close()
	r, err := s.bind(pending(s))
	if err != nil || r.Thread != id1 {
		t.Fatal("not root metadata only", err)
	}
}
func TestRedirectedAndCorruptStateRefused(t *testing.T) {
	s := fixture(t)
	other := filepath.Join(t.TempDir(), "other")
	os.WriteFile(other, []byte("original"), 0600)
	p := filepath.Join(s.StateDir, "codex-thread.json")
	os.Symlink(other, p)
	if _, err := s.read(); err == nil {
		t.Fatal("redirected thread read")
	}
	b, _ := os.ReadFile(other)
	if string(b) != "original" {
		t.Fatal("outside state changed")
	}
	os.Remove(p)
	os.WriteFile(p, []byte("{"), 0600)
	if _, err := s.read(); !errors.Is(err, ErrHeld) {
		t.Fatal("corrupt thread accepted", err)
	}
}
func TestFreshStartHasNoSyntheticConversationID(t *testing.T) {
	s := fixture(t)
	args := s.Args("")
	if slices.Contains(args, "resume") || slices.Contains(args, "--session-id") {
		t.Fatal(args)
	}
	if !slices.Contains(args, "workspace-write") || !slices.Contains(args, "on-request") {
		t.Fatal(args)
	}
	if err := s.Run(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.StateDir, "codex-thread.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("idle session started actor")
	}
}

func TestRetainedProviderConfigurationCannotChange(t *testing.T) {
	s := fixture(t)
	r := pending(s)
	r.State, r.Thread = "bound", id1
	if err := s.write(r); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Supervisor){func(x *Supervisor) { x.Seat = "another" }, func(x *Supervisor) { x.Workspace = "/other" }, func(x *Supervisor) { x.Env = []string{"NEW_CONFIGURATION=1"} }} {
		other := s
		change(&other)
		if _, err := other.read(); !errors.Is(err, ErrHeld) {
			t.Fatal("retained binding changed", err)
		}
	}
}
func TestRedirectedRolloutRefused(t *testing.T) {
	s := fixture(t)
	outside := rollout(t, s, "original", id1, "cli")
	os.Symlink(outside, filepath.Join(s.Home, "sessions", "redirect.jsonl"))
	if _, err := s.bind(pending(s)); !errors.Is(err, ErrHeld) {
		t.Fatal("redirected metadata accepted", err)
	}
}
func TestRedirectedOrUnpinnedExecutableNeverStarts(t *testing.T) {
	s := fixture(t)
	outside := filepath.Join(t.TempDir(), "binary")
	os.WriteFile(outside, []byte("#!/bin/sh\nexit 0\n"), 0700)
	s.Binary = filepath.Join(t.TempDir(), "binary")
	os.Symlink(outside, s.Binary)
	if err := s.Start(); err == nil {
		t.Fatal("redirected executable launched")
	}
	s.Binary = outside
	if err := s.Start(); err == nil {
		t.Fatal("unpinned executable launched")
	}
	if _, err := os.Stat(filepath.Join(s.StateDir, "codex-thread.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected executable created startup intent")
	}
}

func TestFreshAndResumeUseDeclaredPolicy(t *testing.T) {
	s := fixture(t)
	s.Launch.Sandbox, s.Launch.Approvals = "danger-full-access", "never"
	for _, id := range []string{"", id1} {
		args := s.Args(id)
		for _, want := range []string{"danger-full-access", "never", "fixture-model", "model_reasoning_effort=\"high\"", "sandbox_workspace_write.network_access=true"} {
			if !slices.Contains(args, want) {
				t.Fatal("declaration setting dropped", want, args)
			}
		}
	}
	r := pending(s)
	r.State, r.Thread = "bound", id1
	s.write(r)
	l := *s.Launch
	l.Effort = "low"
	s.Launch = &l
	if _, err := s.read(); !errors.Is(err, ErrHeld) {
		t.Fatal("resume changed declared launch", err)
	}
}
