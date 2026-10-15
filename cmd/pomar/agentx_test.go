package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/manager"
)

// fakeManager answers like a manager whose one job runs for a few polls,
// then ends as end describes.
type fakeManager struct {
	mu    sync.Mutex
	polls map[string]int
	runs  int // polls before the job ends; -1 never ends
	end   manager.Entry
}

func serveFake(t *testing.T, f *fakeManager) string {
	t.Helper()
	dir, _ := os.MkdirTemp("/tmp", "pomarax")
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "m.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/attempts", func(w http.ResponseWriter, r *http.Request) {
		var req manager.StartRequest
		json.NewDecoder(r.Body).Decode(&req)
		json.NewEncoder(w).Encode(manager.Entry{Attempt: req.ID, Command: req.Command, State: manager.StateStarting})
	})
	mux.HandleFunc("GET /v1/attempts/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		id := r.PathValue("id")
		f.polls[id]++
		if f.runs < 0 || f.polls[id] <= f.runs {
			json.NewEncoder(w).Encode(manager.Entry{Attempt: id, State: manager.StateRunning})
			return
		}
		e := f.end
		e.Attempt = id
		json.NewEncoder(w).Encode(e)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func code(n int) *int { return &n }

// run -wait returns the job's own exit code, and Pomar's fixed codes when
// the job didn't exit by itself.
func TestRunWaitReturnsTheJobsOutcome(t *testing.T) {
	for name, c := range map[string]struct {
		end  manager.Entry
		want int
	}{
		"exited 0":       {manager.Entry{State: manager.StateExited, ExitCode: code(0)}, 0},
		"exited 3":       {manager.Entry{State: manager.StateExited, ExitCode: code(3)}, 3},
		"class time out": {manager.Entry{State: manager.StateTimedOut}, exitTimedOut},
		"stopped":        {manager.Entry{State: manager.StateStopped}, exitStopped},
		"failed":         {manager.Entry{State: manager.StateFailed, Reason: "boot"}, exitPomar},
		"lost":           {manager.Entry{State: manager.StateLost}, exitPomar},
	} {
		t.Run(name, func(t *testing.T) {
			sock := serveFake(t, &fakeManager{polls: map[string]int{}, runs: 2, end: c.end})
			var out, errb bytes.Buffer
			rc := run([]string{"run", "-socket", sock, "-wait", "-id", "j1", "--", "/bin/true"}, &out, &errb)
			if rc != c.want {
				t.Fatalf("exit %d, want %d (%s)", rc, c.want, errb.String())
			}
			var e manager.Entry
			if json.Unmarshal(out.Bytes(), &e) != nil || e.State != c.end.State {
				t.Fatalf("final record %s", out.String())
			}
		})
	}
}

// A wait that gives up says so with its own code and leaves the job
// running; pomar wait picks the wait up again.
func TestAWaitThatGivesUpLeavesTheJobRunning(t *testing.T) {
	f := &fakeManager{polls: map[string]int{}, runs: -1}
	sock := serveFake(t, f)
	var out, errb bytes.Buffer
	if rc := run([]string{"run", "-socket", sock, "-wait", "-timeout", "300ms", "-id", "j2", "--", "/bin/true"}, &out, &errb); rc != exitWaitGaveUp {
		t.Fatalf("exit %d, want %d", rc, exitWaitGaveUp)
	}
	if !strings.Contains(errb.String(), "pomar wait -id j2") {
		t.Fatalf("no next step: %s", errb.String())
	}
	f.mu.Lock()
	f.runs, f.end = f.polls["j2"]+1, manager.Entry{State: manager.StateExited, ExitCode: code(0)}
	f.mu.Unlock()
	out.Reset()
	if rc := run([]string{"wait", "-socket", sock, "-id", "j2"}, &out, &errb); rc != 0 {
		t.Fatalf("pomar wait: exit %d", rc)
	}
}

// help -json is a machine-readable catalogue with the exit codes an agent
// may branch on.
func TestHelpJSONIsACatalogue(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := run([]string{"help", "-json"}, &out, &errb); rc != 0 {
		t.Fatalf("exit %d", rc)
	}
	var c struct {
		Schema    string            `json:"schema"`
		Loop      []string          `json:"loop"`
		ExitCodes map[string]string `json:"exit_codes"`
		Commands  []command         `json:"commands"`
	}
	if err := json.Unmarshal(out.Bytes(), &c); err != nil || c.Schema != "pomar.help/v1" || len(c.Loop) == 0 || len(c.Commands) == 0 {
		t.Fatalf("catalogue: %v %s", err, out.String())
	}
	for _, k := range []string{"0", "1", "2", "75", "124", "125", "143"} {
		if c.ExitCodes[k] == "" {
			t.Fatalf("exit code %s isn't described", k)
		}
	}
}

func TestCatalogueDiscoversTrustAndOwnerOperationsWithoutActing(t *testing.T) {
	t.Setenv("POMAR_SOCKET", "/not/a/socket")
	var out, errs bytes.Buffer
	if rc := run([]string{"help", "--json"}, &out, &errs); rc != 0 || errs.Len() != 0 {
		t.Fatalf("rc%d %s", rc, errs.String())
	}
	var c struct {
		Commands []command                  `json:"commands"`
		Owners   []command                  `json:"owner_commands"`
		Flags    map[string][]catalogueFlag `json:"command_flags"`
	}
	if err := json.Unmarshal(out.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	names := map[string]command{}
	for _, entry := range append(c.Commands, c.Owners...) {
		if _, exists := names[entry.Name]; exists {
			t.Fatalf("duplicate command %s", entry.Name)
		}
		names[entry.Name] = entry
	}
	for _, name := range []string{"health", "result verify", "attempt output", "attempt signing-key", "install", "server start", "upgrade stage", "upgrade check", "upgrade apply", "upgrade rollback"} {
		if names[name].Usage == "" || names[name].Output == "" {
			t.Fatalf("missing operation %s", name)
		}
	}
	for _, name := range []string{"upgrade stage", "upgrade check", "upgrade apply", "upgrade rollback"} {
		if !strings.Contains(upgradeHelp, names[name].Usage) {
			t.Fatalf("upgrade usage diverged: %s", names[name].Usage)
		}
	}
	// Reconciliation must not regress the merged POMAR-CC listing/session
	// contract while adding owner discovery from the earlier preparation.
	if !strings.Contains(names["seats"].Usage, "-json") || !strings.Contains(names["seats"].Usage, "-menu") || !strings.Contains(strings.Join(names["seats"].Notes, " "), "never prompts") {
		t.Fatal("catalogue regressed explicit seats listing/menu contract")
	}
	if !strings.Contains(names["session"].Usage, "input NAME INPUT_ID") || !strings.Contains(names["session"].Usage, "-ack-unknown") {
		t.Fatal("catalogue dropped live input/held-operation session interface")
	}
	for _, name := range []string{"health", "run", "wait", "result verify", "attempt output"} {
		if len(c.Flags[name]) == 0 {
			t.Fatalf("missing main-loop flags for %s", name)
		}
	}
}

// A command that needs a manager, with none selected, says how to select
// one, and doctor gives that as its next step.
func TestNoManagerSaysHowToSelectOne(t *testing.T) {
	t.Setenv("POMAR_SOCKET", "")
	t.Setenv("POMAR_DATA_ROOT", "")
	var out, errb bytes.Buffer
	if rc := run([]string{"jobs"}, &out, &errb); rc != 2 || !strings.Contains(errb.String(), "POMAR_SOCKET") {
		t.Fatalf("exit %d: %s", rc, errb.String())
	}
	out.Reset()
	run([]string{"doctor", "-json"}, &out, &errb)
	var checks []diagnostic
	if err := json.Unmarshal(out.Bytes(), &checks); err != nil {
		t.Fatal(err)
	}
	for _, d := range checks {
		if d.Name == "manager" && (d.OK || !strings.Contains(d.Next, "POMAR_SOCKET")) {
			t.Fatalf("manager check %+v", d)
		}
		if d.Name == "pomar-host" && version == "0.0.0-dev" && !d.Skipped {
			t.Fatalf("a source build's missing bundle was a failure: %+v", d)
		}
	}
}

// serveHung answers like a manager that accepts a request and then never
// replies (hang), or drops the connection without a reply.
func serveHung(t *testing.T, drop bool) string {
	t.Helper()
	dir, _ := os.MkdirTemp("/tmp", "pomarax")
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "m.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if drop {
			conn, _, _ := w.(http.Hijacker).Hijack()
			conn.Close()
			return
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { close(release); srv.Close() })
	return sock
}

// -timeout bounds the wait's own calls: a manager that never answers can't
// hold it past the limit.
func TestAWaitIsBoundedWhenTheManagerHangs(t *testing.T) {
	sock := serveHung(t, false)
	var out, errb bytes.Buffer
	start := time.Now()
	rc := run([]string{"wait", "-socket", sock, "-id", "j3", "-timeout", "300ms"}, &out, &errb)
	if rc != exitWaitGaveUp || time.Since(start) > 5*time.Second {
		t.Fatalf("exit %d after %v: %s", rc, time.Since(start), errb.String())
	}
	if !strings.Contains(errb.String(), "unanswered") {
		t.Fatalf("the give-up doesn't say no state was seen: %s", errb.String())
	}
}

// A start whose reply never came may have been admitted: it is looked up by
// its own ID, never started again under a new one.
func TestAnUnansweredStartPointsAtItsOwnID(t *testing.T) {
	sock := serveHung(t, true)
	var out, errb bytes.Buffer
	rc := run([]string{"run", "-socket", sock, "-wait", "-id", "j4", "--", "/bin/true"}, &out, &errb)
	if rc != 1 || !strings.Contains(errb.String(), "pomar attempt get -id j4") || !strings.Contains(errb.String(), "don't start it again") {
		t.Fatalf("exit %d: %s", rc, errb.String())
	}
}
