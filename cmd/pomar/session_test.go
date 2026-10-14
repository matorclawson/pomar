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

// pomar session logs gives a session's durable output, paged, and it's
// readable even for a session that has already exited.
func TestSessionLogsAreDurableAndPaged(t *testing.T) {
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
	if rc := run([]string{"session", "new", "-root", root, "-id", "op-1", "work", "--", "/bin/sh", "-c", "printf '0123456789'"}, &out, &errb); rc != 0 {
		t.Fatalf("new: %d %s", rc, errb.String())
	}
	var logged string
	for i := 0; i < 200 && !strings.Contains(logged, "0123456789"); i++ {
		out.Reset()
		run([]string{"session", "logs", "-root", root, "work"}, &out, &errb)
		logged = out.String()
	}
	if !strings.Contains(logged, "0123456789") {
		t.Fatalf("the full log: %q", logged)
	}
	out.Reset()
	if rc := run([]string{"session", "logs", "-root", root, "-from", "0", "-limit", "5", "work"}, &out, &errb); rc != 0 || out.Len() != 5 {
		t.Fatalf("a 5-byte page: %d %q", rc, out.String())
	}
	tmp := filepath.Join(dir, "out.log")
	if rc := run([]string{"session", "logs", "-root", root, "-o", tmp, "work"}, &out, &errb); rc != 0 {
		t.Fatalf("logs -o: %d %s", rc, errb.String())
	}
	b, err := os.ReadFile(tmp)
	if err != nil || !strings.Contains(string(b), "0123456789") {
		t.Fatalf("logs -o %q: %v", tmp, err)
	}
	if rc := run([]string{"session", "logs", "-root", root, "none"}, &out, &errb); rc != exitNotFound {
		t.Fatalf("logs of an unknown name: %d", rc)
	}
}

// pomar session paste sends a whole file (or stdin) as one write, bracketed
// as a paste unless -raw, through the same fenced send as a plain send.
func TestSessionPasteBracketsAndFences(t *testing.T) {
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
	// cat -v makes control bytes visible as text, so the screen shows
	// whether the markers arrived.
	if rc := run([]string{"session", "new", "-root", root, "-id", "op-1", "-cols", "80", "-rows", "6", "work", "--", "/bin/cat", "-v"}, &out, &errb); rc != 0 {
		t.Fatalf("new: %d %s", rc, errb.String())
	}

	// From a file.
	payload := filepath.Join(dir, "p.txt")
	if err := os.WriteFile(payload, []byte("line one\nline two"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	pr, pw, _ := os.Pipe()
	pw.Close()
	if rc := sessionCmd([]string{"paste", "-root", root, "-id", "paste-1", "-file", payload, "work"}, pr, &out, &errb); rc != 0 {
		t.Fatalf("paste -file: %d %s", rc, errb.String())
	}
	var res sessiond.OpResult
	if json.Unmarshal(out.Bytes(), &res) != nil || !res.Written {
		t.Fatalf("paste printed %s", out.String())
	}
	var screen string
	for i := 0; i < 200 && !strings.Contains(screen, "line two"); i++ {
		out.Reset()
		run([]string{"session", "screen", "-root", root, "work"}, &out, &errb)
		screen = out.String()
	}
	if !strings.Contains(screen, "^[[200~line one") || !strings.Contains(screen, "line two^[[201~") {
		t.Fatalf("no bracketed-paste markers around the file's content: %q", screen)
	}

	// From stdin, -raw: no markers.
	pr2, pw2, _ := os.Pipe()
	pw2.Write([]byte("rawtext"))
	pw2.Close()
	out.Reset()
	if rc := sessionCmd([]string{"paste", "-root", root, "-id", "paste-2", "-raw", "work"}, pr2, &out, &errb); rc != 0 {
		t.Fatalf("paste -raw from stdin: %d %s", rc, errb.String())
	}
	screen = ""
	for i := 0; i < 200 && !strings.Contains(screen, "rawtext"); i++ {
		out.Reset()
		run([]string{"session", "screen", "-root", root, "work"}, &out, &errb)
		screen = out.String()
	}
	if strings.Contains(screen, "[200~rawtext") {
		t.Fatal("-raw still bracketed the payload")
	}
	if !strings.Contains(screen, "rawtext") {
		t.Fatalf("the raw stdin payload never arrived: %q", screen)
	}

	// A stale epoch refuses a paste exactly like it refuses a send: nothing sent.
	pr3, pw3, _ := os.Pipe()
	pw3.Write([]byte("should-not-land"))
	pw3.Close()
	out.Reset()
	if rc := sessionCmd([]string{"paste", "-root", root, "-id", "paste-3", "-epoch", "999", "work"}, pr3, &out, &errb); rc != exitStale {
		t.Fatalf("a stale epoch: %d %s", rc, errb.String())
	}
	out.Reset()
	run([]string{"session", "screen", "-root", root, "work"}, &out, &errb)
	if strings.Contains(out.String(), "should-not-land") {
		t.Fatal("a stale paste still wrote its payload")
	}

	// Over the bound: refused, nothing sent.
	big := filepath.Join(dir, "big.txt")
	if err := os.WriteFile(big, make([]byte, maxPasteBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	pr4, pw4, _ := os.Pipe()
	pw4.Close()
	if rc := sessionCmd([]string{"paste", "-root", root, "-id", "paste-4", "-file", big, "work"}, pr4, &out, &errb); rc != 2 {
		t.Fatalf("over the paste bound: %d %s", rc, errb.String())
	}
}

// pomar session scrollback reads history without attaching, and -lines
// bounds it; pomar session health is a passive, heuristic screen read.
func TestSessionScrollbackAndHealth(t *testing.T) {
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
	script := "i=1; while [ $i -le 10 ]; do printf 'l%02d\\n' $i; i=$((i+1)); done; printf 'panic: boom\\n'; sleep 30"
	if rc := run([]string{"session", "new", "-root", root, "-id", "op-1", "-rows", "3", "work", "--", "/bin/sh", "-c", script}, &out, &errb); rc != 0 {
		t.Fatalf("new: %d %s", rc, errb.String())
	}
	var scr string
	for i := 0; i < 200 && !strings.Contains(scr, "panic"); i++ {
		out.Reset()
		run([]string{"session", "screen", "-root", root, "work"}, &out, &errb)
		scr = out.String()
	}
	out.Reset()
	if rc := run([]string{"session", "scrollback", "-root", root, "work"}, &out, &errb); rc != 0 {
		t.Fatalf("scrollback: %d %s", rc, errb.String())
	}
	if !strings.Contains(out.String(), "l01") {
		t.Fatalf("scrollback should reach past the 3-row screen: %q", out.String())
	}
	out.Reset()
	if rc := run([]string{"session", "scrollback", "-root", root, "-lines", "2", "-json", "work"}, &out, &errb); rc != 0 {
		t.Fatalf("scrollback -lines -json: %d %s", rc, errb.String())
	}
	var sb seatterm.ScrollbackText
	if json.Unmarshal(out.Bytes(), &sb) != nil || len(sb.Lines) != 2 || !sb.Truncated {
		t.Fatalf("bounded scrollback: %s", out.String())
	}
	out.Reset()
	if rc := run([]string{"session", "health", "-root", root, "work"}, &out, &errb); rc != 0 {
		t.Fatalf("health: %d %s", rc, errb.String())
	}
	var h seatterm.Health
	if json.Unmarshal(out.Bytes(), &h) != nil || !h.PossiblePanic || h.PossibleReadonlyRefusal || h.PossibleApprovalPrompt {
		t.Fatalf("health should flag only possible_panic: %s", out.String())
	}
}

// -expected-sha256 refuses a launch whose binary doesn't match.
func TestSessionNewExpectedSHA256Refuses(t *testing.T) {
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
	if rc := run([]string{"session", "new", "-root", root, "-id", "op-1", "-expected-sha256", strings.Repeat("0", 64), "work", "--", "/bin/sh", "-c", "echo ok"}, &out, &errb); rc == 0 {
		t.Fatalf("a mismatched expected-sha256 should refuse the launch: %s", out.String())
	}
}
