package sessiond

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/seatterm"
	"github.com/zeroemployeeorg/pomar/internal/termstate"
)

// root is a private root short enough for a Unix socket path.
func root(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "psd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "r")
}

// serve runs a service on r until the test ends.
func serve(t *testing.T, r string) (*Server, *Client) {
	t.Helper()
	s, err := Open(r)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		if err := s.Serve(ctx, func() { close(ready) }); err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-ready:
	case <-done:
		t.Fatal("the service didn't start")
	}
	t.Cleanup(func() {
		cancel()
		<-done
		s.Close()
	})
	return s, NewClient(r)
}

func shell(op, name, script string) CreateRequest {
	return CreateRequest{Operation: op, Name: name, Path: "/bin/sh", Args: []string{"-c", script}, Env: []string{"TERM=xterm-256color", "PATH=/usr/bin:/bin"}, Cols: 60, Rows: 8}
}

func screenOf(t *testing.T, c *Client, name string) seatterm.ScreenText {
	t.Helper()
	var scr seatterm.ScreenText
	if err := c.Do("GET", "/v1/sessions/"+name+"/screen", nil, &scr); err != nil {
		t.Fatal(err)
	}
	return scr
}

func waitScreen(t *testing.T, c *Client, name, want string) seatterm.ScreenText {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if scr := screenOf(t, c, name); strings.Contains(strings.Join(scr.Lines, "\n"), want) {
			return scr
		}
	}
	t.Fatalf("the screen never showed %q: %q", want, screenOf(t, c, name).Lines)
	return seatterm.ScreenText{}
}

func kindOf(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Kind
	}
	return ""
}

// lockedBuffer is a bytes.Buffer safe to read while a pump writes it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]byte(nil), l.b.Bytes()...)
}

// A session's whole life through the service: made once per operation,
// written to, read as text, entered and left with its exact screen, stopped
// once per operation, and its name taken by a new generation.
func TestASessionsLifeThroughTheService(t *testing.T) {
	_, c := serve(t, root(t))
	var made, again Created
	req := shell("op-1", "work", `printf 'ready\n'; while read l; do printf 'got:%s\n' "$l"; done`)
	if err := c.Do("POST", "/v1/sessions", req, &made); err != nil || !made.Created || !made.Running {
		t.Fatalf("create: %v %+v", err, made)
	}
	if err := c.Do("POST", "/v1/sessions", req, &again); err != nil || again.Created || again.ID != made.ID {
		t.Fatalf("a retried create made another session: %v %+v", err, again)
	}
	other := shell("op-2", "work", "sleep 30")
	if err := c.Do("POST", "/v1/sessions", other, nil); kindOf(err) != KindConflict {
		t.Fatalf("a running name was replaced: %v", err)
	}
	waitScreen(t, c, "work", "ready")

	var sent, resent OpResult
	send := SendRequest{Operation: "send-1", Text: "one\r"}
	if err := c.Do("POST", "/v1/sessions/work/send", send, &sent); err != nil || sent.Outcome != "written" {
		t.Fatalf("send: %v %+v", err, sent)
	}
	if err := c.Do("POST", "/v1/sessions/work/send", send, &resent); err != nil || resent != sent {
		t.Fatalf("a retried send: %v %+v", err, resent)
	}
	scr := waitScreen(t, c, "work", "got:one")
	if n := strings.Count(strings.Join(scr.Lines, "\n"), "got:one"); n != 1 {
		t.Fatalf("a retried send was written again: %d times", n)
	}

	// A viewer enters, sees the exact screen, and its typing reaches nothing.
	st, err := c.Attach("work", true, false)
	if err != nil {
		t.Fatal(err)
	}
	in, inW := io.Pipe()
	out := &lockedBuffer{}
	var notices []string
	var nmu sync.Mutex
	pumped := make(chan bool, 1)
	go func() {
		d, _ := Pump(st, in, out, 60, 8, nil, func(n string) { nmu.Lock(); notices = append(notices, n); nmu.Unlock() })
		pumped <- d
	}()
	inW.Write([]byte("ignored\r"))
	if err := c.Do("POST", "/v1/sessions/work/send", SendRequest{Operation: "send-2", Text: "two\r"}, nil); err != nil {
		t.Fatal(err)
	}
	waitScreen(t, c, "work", "got:two")
	for end := time.Now().Add(5 * time.Second); !bytes.Contains(out.Bytes(), []byte("got:two")) && time.Now().Before(end); {
		time.Sleep(20 * time.Millisecond)
	}
	model := termstate.New(60, 8, 0)
	model.Feed(out.Bytes())
	want := screenOf(t, c, "work")
	for y, line := range want.Lines {
		if model.Row(y) != line {
			t.Fatalf("the viewer's row %d is %q, the session's %q", y, model.Row(y), line)
		}
	}
	if strings.Contains(strings.Join(want.Lines, "\n"), "ignored") {
		t.Fatal("a viewer's typing reached the program")
	}
	inW.Write([]byte{DetachKey})
	select {
	case d := <-pumped:
		if !d {
			t.Fatal("the detach key didn't detach")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the detach key didn't detach")
	}
	nmu.Lock()
	if !strings.Contains(strings.Join(notices, "|"), "your input isn't sent") {
		t.Fatalf("the viewer wasn't told it views: %q", notices)
	}
	nmu.Unlock()
	var info seatterm.SessionInfo
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if c.Do("GET", "/v1/sessions/work", nil, &info); len(info.Viewers) == 0 {
			break
		}
	}
	if !info.Running || len(info.Viewers) != 0 {
		t.Fatalf("detaching stopped the program, or left a viewer: %+v", info)
	}

	// A controller types through its attach.
	st, err = c.Attach("work", false, false)
	if err != nil {
		t.Fatal(err)
	}
	in, inW = io.Pipe()
	go Pump(st, in, io.Discard, 60, 8, nil, nil)
	inW.Write([]byte("three\r"))
	waitScreen(t, c, "work", "got:three")
	inW.Write([]byte{DetachKey})

	var stopped, restopped OpResult
	if err := c.Do("POST", "/v1/sessions/work/stop", StopRequest{Operation: "stop-1"}, &stopped); err != nil || stopped.Outcome != "stopped" || stopped.Session != made.ID {
		t.Fatalf("stop: %v %+v", err, stopped)
	}
	var next Created
	if err := c.Do("POST", "/v1/sessions", shell("op-3", "work", "sleep 30"), &next); err != nil || !next.Created || next.ID == made.ID {
		t.Fatalf("the ended name wasn't taken by a new generation: %v %+v", err, next)
	}
	if err := c.Do("POST", "/v1/sessions/work/stop", StopRequest{Operation: "stop-1"}, &restopped); err != nil || restopped != stopped {
		t.Fatalf("a retried stop acted again: %v %+v", err, restopped)
	}
	if err := c.Do("GET", "/v1/sessions/work", nil, &info); err != nil || !info.Running || info.ID != next.ID {
		t.Fatalf("a retried stop reached the new generation: %v %+v", err, info)
	}
	if err := c.Do("GET", "/v1/sessions/none", nil, nil); kindOf(err) != KindNotFound {
		t.Fatalf("an unknown name: %v", err)
	}
}

// A root that is a link, isn't owned privately, or isn't a directory is
// refused; a second service on a served root is refused.
func TestTheRootIsPrivate(t *testing.T) {
	r := root(t)
	if err := PrepareRoot(r); err != nil {
		t.Fatal(err)
	}
	os.Chmod(r, 0o750)
	if err := CheckRoot(r); err == nil {
		t.Fatal("a root open to its group was accepted")
	}
	os.Chmod(r, 0o700)
	link := filepath.Join(filepath.Dir(r), "link")
	os.Symlink(r, link)
	if err := CheckRoot(link); err == nil {
		t.Fatal("a linked root was accepted")
	}
	file := filepath.Join(filepath.Dir(r), "file")
	os.WriteFile(file, nil, 0o600)
	if _, err := Open(file); err == nil {
		t.Fatal("a file was accepted as a root")
	}
	if err := PrepareRoot("relative/root"); err == nil {
		t.Fatal("a relative root was accepted")
	}
	s, err := Open(r)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := Open(r); !errors.Is(err, ErrServing) {
		t.Fatalf("a second service on one root: %v", err)
	}
}

// A connection whose peer can't be verified as this user is closed, and
// journaled as refused.
func TestAnUnverifiedPeerIsRefused(t *testing.T) {
	r := root(t)
	s, err := Open(r)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback listener:", err)
	}
	defer tcp.Close()
	go (&ownerListener{Listener: tcp, s: s}).Accept()
	conn, err := net.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("the connection wasn't closed: %v", err)
	}
	b, _ := os.ReadFile(filepath.Join(r, journalName))
	if !bytes.Contains(b, []byte(`"action":"connect","phase":"outcome","principal":"","session":"","outcome":"refused"`)) {
		t.Fatalf("the refusal wasn't journaled:\n%s", b)
	}
}

// A session an earlier service held, and never saw end, is reported out of
// reach once, and never as exited.
func TestAnEarlierServicesSessionsAreOutOfReach(t *testing.T) {
	r := root(t)
	if err := PrepareRoot(r); err != nil {
		t.Fatal(err)
	}
	var lines []byte
	for _, rec := range []Record{
		{AuditRecord: seatterm.AuditRecord{Action: "create", Phase: "outcome", Outcome: "ok", Session: "s-live"}, Serve: "old"},
		{AuditRecord: seatterm.AuditRecord{Action: "name", Phase: "outcome", Outcome: "ok", Session: "s-live"}, Serve: "old", Name: "agent"},
		{AuditRecord: seatterm.AuditRecord{Action: "create", Phase: "outcome", Outcome: "ok", Session: "s-ended"}, Serve: "old"},
		{AuditRecord: seatterm.AuditRecord{Action: "exit", Phase: "outcome", Outcome: "ok", Session: "s-ended"}, Serve: "old"},
	} {
		b, _ := json.Marshal(rec)
		lines = append(append(lines, b...), '\n')
	}
	lines = append(lines, `{"torn`...)
	os.WriteFile(filepath.Join(r, journalName), lines, 0o600)
	s, err := Open(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.unrecovered) != 1 || s.unrecovered[0].ID != "s-live" || s.unrecovered[0].Name != "agent" {
		t.Fatalf("unrecovered %+v", s.unrecovered)
	}
	s.Close()
	b, _ := os.ReadFile(filepath.Join(r, journalName))
	if !bytes.Contains(b, []byte(`"session":"s-live","outcome":"out-of-reach"`)) {
		t.Fatalf("journal:\n%s", b)
	}
	// The next service doesn't report it again: it was reconciled.
	_, c := serve(t, r)
	var l Listing
	if err := c.Do("GET", "/v1/sessions", nil, &l); err != nil || len(l.Unrecovered) != 0 {
		t.Fatalf("reported again: %v %+v", err, l.Unrecovered)
	}
}
