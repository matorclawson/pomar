package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
