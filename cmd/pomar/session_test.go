package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeroemployeeorg/pomar/internal/seatterm"
	"github.com/zeroemployeeorg/pomar/internal/sessiond"
)

// pomar session's refusals carry fixed exit codes, and its output is JSON.
func TestSessionCommandsHaveFixedExitCodes(t *testing.T) {
	dir, _ := os.MkdirTemp("/tmp", "psc")
	t.Cleanup(func() { os.RemoveAll(dir) })
	root := filepath.Join(dir, "r")
	var out, errb bytes.Buffer
	if rc := run([]string{"session", "ls", "-root", root}, &out, &errb); rc != exitNoService || !strings.Contains(errb.String(), "pomar session serve") {
		t.Fatalf("no service: %d %s", rc, errb.String())
	}
	if rc := run([]string{"session", "new", "-root", root, "work", "--", "/bin/sh"}, &out, &errb); rc != 2 {
		t.Fatalf("a new without -id: %d", rc)
	}
	s, err := sessiond.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	ready, done := make(chan struct{}), make(chan struct{})
	go func() { defer close(done); s.Serve(ctx, func() { close(ready) }) }()
	<-ready
	defer func() { cancel(); <-done }()

	out.Reset()
	if rc := run([]string{"session", "new", "-root", root, "-id", "op-1", "-cols", "40", "-rows", "6", "-env", "GREETING=hi", "work", "--", "/bin/sh", "-c", `printf '%s\n' "$GREETING"; read l; printf 'got:%s\n' "$l"; sleep 30`}, &out, &errb); rc != 0 {
		t.Fatalf("new: %d %s", rc, errb.String())
	}
	var made sessiond.Created
	if json.Unmarshal(out.Bytes(), &made) != nil || !made.Created || made.Name != "work" {
		t.Fatalf("new printed %s", out.String())
	}
	if rc := run([]string{"session", "new", "-root", root, "-id", "op-2", "work", "--", "/bin/sh"}, &out, &errb); rc != exitConflict {
		t.Fatalf("a running name: %d", rc)
	}
	if rc := run([]string{"session", "show", "-root", root, "none"}, &out, &errb); rc != exitNotFound {
		t.Fatalf("an unknown name: %d", rc)
	}
	if rc := run([]string{"session", "send", "-root", root, "-id", "s-1", "-enter", "work", "hello"}, &out, &errb); rc != 0 {
		t.Fatalf("send: %d %s", rc, errb.String())
	}
	var screen string
	for i := 0; i < 200 && !strings.Contains(screen, "got:hello"); i++ {
		out.Reset()
		run([]string{"session", "screen", "-root", root, "work"}, &out, &errb)
		screen = out.String()
	}
	if !strings.Contains(screen, "hi\n") || !strings.Contains(screen, "got:hello") {
		t.Fatalf("screen %q", screen)
	}
	if rc := run([]string{"session", "stop", "-root", root, "-id", "k-1", "work"}, &out, &errb); rc != 0 {
		t.Fatalf("stop: %d %s", rc, errb.String())
	}
	if rc := run([]string{"session", "send", "-root", root, "-id", "s-2", "work", "late"}, &out, &errb); rc != exitExited {
		t.Fatalf("a send to an ended session: %d %s", rc, errb.String())
	}
}

// A new session's environment is exactly TERM, HOME, PATH and LANG from the
// caller's, then each -env: nothing else of the caller's.
func TestASessionsEnvironmentIsExplicit(t *testing.T) {
	t.Setenv("SECRET_LOOKING", "x")
	t.Setenv("TERM", "")
	env := strings.Join(sessionEnv([]string{"A=1", "TERM=vt100"}), " ")
	if strings.Contains(env, "SECRET_LOOKING") || !strings.Contains(env, "TERM=vt100") || !strings.Contains(env, "A=1") {
		t.Fatalf("env %s", env)
	}
}

// Text after -- is sent as it is, even beginning with a dash; a stale epoch
// and a when-ready send to a session without a state channel have their
// own exit codes, and write nothing.
func TestSessionSendsDashTextAndFencedRefusals(t *testing.T) {
	dir, _ := os.MkdirTemp("/tmp", "psc")
	t.Cleanup(func() { os.RemoveAll(dir) })
	root := filepath.Join(dir, "r")
	s, err := sessiond.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	ready, done := make(chan struct{}), make(chan struct{})
	go func() { defer close(done); s.Serve(ctx, func() { close(ready) }) }()
	<-ready
	defer func() { cancel(); <-done }()
	var out, errb bytes.Buffer
	if rc := run([]string{"session", "new", "-root", root, "-id", "op-1", "-cols", "40", "-rows", "6", "work", "--", "/bin/sh", "-c", `while read l; do printf 'got:%s\n' "$l"; done`}, &out, &errb); rc != 0 {
		t.Fatalf("new: %d %s", rc, errb.String())
	}
	out.Reset()
	if rc := run([]string{"session", "send", "-root", root, "-id", "s-1", "-enter", "work", "--", "-dashed"}, &out, &errb); rc != 0 {
		t.Fatalf("send -- -dashed: %d %s", rc, errb.String())
	}
	var res sessiond.OpResult
	if json.Unmarshal(out.Bytes(), &res) != nil || res.Mode != "raw" || !res.Written || res.Accepted != "unsupported" {
		t.Fatalf("send printed %s", out.String())
	}
	var screen string
	for i := 0; i < 200 && !strings.Contains(screen, "got:-dashed"); i++ {
		out.Reset()
		run([]string{"session", "screen", "-root", root, "work"}, &out, &errb)
		screen = out.String()
	}
	if !strings.Contains(screen, "got:-dashed") {
		t.Fatalf("screen %q", screen)
	}
	if rc := run([]string{"session", "send", "-root", root, "-id", "s-2", "-epoch", "999", "work", "late"}, &out, &errb); rc != exitStale {
		t.Fatalf("a stale epoch: %d %s", rc, errb.String())
	}
	if rc := run([]string{"session", "send", "-root", root, "-id", "s-3", "-when-ready", "work", "late"}, &out, &errb); rc != exitUnsupp {
		t.Fatalf("when-ready without a state channel: %d %s", rc, errb.String())
	}
	out.Reset()
	if rc := run([]string{"session", "stop", "-root", root, "-id", "k-1", "work"}, &out, &errb); rc != 0 || !strings.Contains(out.String(), `"group": "gone"`) {
		t.Fatalf("stop: %d %s", rc, out.String())
	}
}

// The attach status is written as a title of printable text only, and only
// once there is a role to say.
func TestTheAttachStatusTitleIsPrintableOnly(t *testing.T) {
	var shown []string
	a := &attachStatus{name: "work\x07\x1b]0;evil", agent: "unknown", show: func(s string) { shown = append(shown, s) }}
	a.state(seatterm.AgentState{State: "waiting-input"})
	if len(shown) != 0 {
		t.Fatal("a status was shown before presence")
	}
	a.presence(seatterm.PresenceMsg{You: "controller", Viewers: []string{"uid:1", "uid:1"}, Epoch: 3})
	var b bytes.Buffer
	a.flush(&b)
	got := b.String()
	if !strings.HasPrefix(got, "\x1b]2;pomar work]0;evil: controller (epoch 3), 2 attached, agent waiting-input") || strings.Count(got, "\x07") != 1 || strings.Count(got, "\x1b") != 1 {
		t.Fatalf("title %q", got)
	}
	b.Reset()
	a.flush(&b)
	if b.Len() != 0 {
		t.Fatal("a title was written twice")
	}
}
