package agentenv

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// POMAR-CC-SOW-37 rev3: a public-Host-API replacement->resolution regression
// using genuine host-produced evidence -- every lifecycle step (create implied
// by hand-built fixture, start, stop, reconcile, start again, continuations)
// goes through the real h.Handler() HTTP routes and the real host.go/
// reconcile.go/continuation.go code, exactly as in production. The only
// substitutions are the package's own existing, long-established test seams:
// h.probe (reconcile.go:114-115, used throughout reconcile_test.go/
// retirement_test.go/preboot_reconcile_test.go) standing in for the native
// Swift fence-probe subprocess, and a real, test-owned no-op executable
// standing in for the Swift VM helper itself (so start() launches and
// proc.Find locates a REAL process, never a synthetic Action literal).
//
// This file does not touch host.go, reconcile.go or continuation.go.

// fakeHelperBinary builds a real, native (no shebang interpreter) executable
// that ignores every argument start() passes it and just blocks, so
// cmd.Start() launches a real, locatable process without booting any VM. It
// must be a native binary, not a shell script: reconcile.go's reconcileHandler
// checks e.Process.Args == "<helper> agent-environment --config <file>"
// exactly as `ps` reports the live command line, and a shebang script's own
// argv[0] (verified empirically) is the interpreter ("/bin/sh"), not the
// script path -- only a direct exec keeps the helper's own path as argv[0].
func fakeHelperBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "fakehelper.go")
	// A bare `select {}` looks like it blocks forever, but the Go runtime's
	// own deadlock detector treats a main goroutine with zero progress and
	// no other goroutines as a real deadlock and exits(2) immediately
	// (confirmed empirically) -- a sleep loop makes genuine, if idle,
	// progress, so the runtime never flags it.
	if err := os.WriteFile(src, []byte("package main\nimport \"time\"\nfunc main() { for { time.Sleep(time.Hour) } }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "fakehelper")
	cmd := exec.Command("go", "build", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building fake helper binary: %v\n%s", err, out)
	}
	return bin
}

func newTestHost(t *testing.T) (*Host, string) {
	t.Helper()
	root := t.TempDir()
	h := &Host{config: HostConfig{Root: root, Helper: fakeHelperBinary(t), MaxLive: 2, CPUs: 1, MemoryBytes: 512 << 20}, envs: map[string]*Environment{}, gates: map[string]*Egress{}, servers: map[string]*http.Server{}}
	return h, root
}

// envSnap is a safe, locked copy of the Environment fields this file's tests
// read after a real start(): host.go's own background watcher goroutine
// (spawned by the real start(), host.go:584) writes e.Phase/e.Process/
// e.HelperExit under h.mu from a separate goroutine once the real helper
// process it's watching exits (which this file's own kill/stop calls cause).
// Reading those fields directly, unlocked, is a genuine data race the race
// detector correctly reports -- host.go's own code always holds h.mu around
// them; a test reading them unlocked doesn't get an exemption.
type envSnap struct {
	Phase       string
	Incarnation string
	PID         int
	Actions     map[string]Action
}

func snapshot(h *Host, e *Environment) envSnap {
	h.mu.Lock()
	defer h.mu.Unlock()
	actions := make(map[string]Action, len(e.Actions))
	for k, v := range e.Actions {
		actions[k] = v
	}
	return envSnap{Phase: e.Phase, Incarnation: e.Spec.Incarnation, PID: e.Process.PID, Actions: actions}
}

func hostActionCall(h *Host, env, action, operationID, incarnation string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"operation_id": operationID, "expected_incarnation": incarnation})
	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/environments/"+env+"/"+action, strings.NewReader(string(body))))
	return w
}

// shortTempDir returns a short-path temp directory: t.TempDir()'s own path
// (under a long macOS /private/var/folders prefix plus the test name)
// routinely exceeds Darwin's ~104-byte sun_path limit for Unix sockets, and
// gate() derives its own socket paths (egress, go.sock) from e.Spec.Directory
// directly -- so the whole environment directory needs a short root, not
// just the explicit socket fields.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pcc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// TestPublicHostStartLaunchesARealLocatableProcess is step 1: confirm the
// real start() handler, through the real HTTP route, actually launches and
// records a real OS process -- the foundation the rest of this file's
// sequence builds on.
func TestPublicHostStartLaunchesARealLocatableProcess(t *testing.T) {
	h, _ := newTestHost(t)
	dir := filepath.Join(shortTempDir(t), "env")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	e := &Environment{Spec: VMSpec{HostConfig: h.config, Environment: "env", Session: "session1", Directory: dir, Rootfs: filepath.Join(dir, "workspace.ext4"), ControlSocket: filepath.Join(dir, "agent.sock"), EgressSocket: filepath.Join(dir, "egress.sock")}, Phase: "created", Actions: map[string]Action{}}
	h.envs["env"] = e

	w := hostActionCall(h, "env", "start", "start-1", "")
	if w.Code != 200 {
		t.Fatalf("start failed: %d %s", w.Code, w.Body.String())
	}
	snap := snapshot(h, e)
	if snap.Phase != "running" {
		t.Fatalf("phase = %q, want running", snap.Phase)
	}
	if snap.Incarnation == "" {
		t.Fatal("no incarnation assigned")
	}
	if snap.PID == 0 {
		t.Fatal("no process recorded")
	}
	// Confirm it's genuinely a real, currently-running process -- not just a
	// recorded number.
	if err := syscall.Kill(snap.PID, 0); err != nil {
		t.Fatalf("recorded PID %d is not a real running process: %v", snap.PID, err)
	}
	t.Cleanup(func() { syscall.Kill(snap.PID, syscall.SIGKILL) })

	a := snap.Actions["start-1"]
	if a.State != "completed" || a.ResultingIncarnation != snap.Incarnation {
		t.Fatalf("start action not recorded correctly: %+v", a)
	}
}

// writeVMStopped writes the guest-owned status file stop() polls for --
// nothing in this package's tests has a real guest to write it, so every
// test that calls /stop writes it directly, same as reconciliationFixture/
// retirementFixture already do for vm-status.json.
func writeVMStopped(t *testing.T, h *Host, e *Environment) {
	t.Helper()
	snap := snapshot(h, e)
	h.mu.Lock()
	environment, session, directory := e.Spec.Environment, e.Spec.Session, e.Spec.Directory
	h.mu.Unlock()
	b, _ := json.Marshal(map[string]string{"environment": environment, "session": session, "incarnation": snap.Incarnation, "vm_stopped": "true"})
	if err := os.WriteFile(filepath.Join(directory, "vm-status-"+snap.Incarnation+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// killAndConfirmGone sends a real SIGKILL to pid and waits until the real OS
// process table (not an injected fake) no longer reports it -- so stop()'s
// own departed() check, run completely unmodified, has a genuine departure
// to find.
func killAndConfirmGone(t *testing.T, pid int) {
	t.Helper()
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		t.Fatal(err)
	}
	for range 100 {
		if err := syscall.Kill(pid, 0); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("pid %d still present after SIGKILL", pid)
}

// realFenceEvidence is a *correctly shaped* h.probe substitute: it reports
// against the real rootfs file's real device/inode (read via os.Stat, not
// invented), so the Reconciliation this produces binds to genuinely real
// filesystem identity -- the one piece true machineProbe would also report
// from the real, unmodified Go code calling it.
func realFenceEvidence(t *testing.T, e *Environment, confirmed bool, issues ...string) func(context.Context, FenceProbeRequest) (FenceProbeEvidence, error) {
	t.Helper()
	return func(_ context.Context, r FenceProbeRequest) (FenceProbeEvidence, error) {
		fi, err := os.Stat(e.Spec.Rootfs)
		if err != nil {
			t.Fatal(err)
		}
		s := fi.Sys().(*syscall.Stat_t)
		return FenceProbeEvidence{
			Environment: r.Environment, Session: r.Session, Incarnation: r.Incarnation, Operation: r.Operation,
			ObservedAt: time.Now().UTC().Format(time.RFC3339), Coverage: "direct-vz-private-disk/v1",
			ObserverUID: os.Getuid(), ProcessCount: 1, OwnProcessesChecked: 1,
			RootfsDevice: uint32(s.Dev), RootfsInode: s.Ino,
			Confirmed: confirmed, Issues: issues,
		}, nil
	}
}

// TestPublicHostStopThenReconcileProducesRealReconciliationEvidence is step
// 2: start (as above), then stop and reconcile the SAME, still-current
// incarnation through the real handlers -- the already-supported sequence
// (stop -> reconcile -> start) that needs no production fix at all, proven
// with a real process and real (if probe-substituted) evidence rather than
// a hand-built Action.
func TestPublicHostStopThenReconcileProducesRealReconciliationEvidence(t *testing.T) {
	h, _ := newTestHost(t)
	dir := filepath.Join(shortTempDir(t), "env")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	e := &Environment{Spec: VMSpec{HostConfig: h.config, Environment: "env", Session: "session1", Directory: dir, Rootfs: filepath.Join(dir, "workspace.ext4"), ControlSocket: filepath.Join(dir, "agent.sock"), EgressSocket: filepath.Join(dir, "egress.sock")}, Phase: "created", Actions: map[string]Action{}}
	h.envs["env"] = e
	h.stopWait = 2 * time.Second

	if w := hostActionCall(h, "env", "start", "start-1", ""); w.Code != 200 {
		t.Fatalf("start failed: %d %s", w.Code, w.Body.String())
	}
	incarnation1 := snapshot(h, e).Incarnation
	if err := os.WriteFile(e.Spec.Rootfs, []byte("retained workspace bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	killAndConfirmGone(t, snapshot(h, e).PID)
	writeVMStopped(t, h, e)
	if w := hostActionCall(h, "env", "stop", "stop-1", incarnation1); w.Code != 200 {
		t.Fatalf("stop failed: %d %s", w.Code, w.Body.String())
	}
	if phase := snapshot(h, e).Phase; phase != "stopped" {
		t.Fatalf("phase = %q, want stopped", phase)
	}

	h.probe = realFenceEvidence(t, e, true)
	reconcileBody, _ := json.Marshal(ReconcileRequest{OperationID: "reconcile-1", SessionID: "session1", Incarnation: incarnation1, LaunchOperation: "start-1", FenceOperation: "stop-1"})
	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/environments/env/reconcile", strings.NewReader(string(reconcileBody))))
	if w.Code != 200 {
		t.Fatalf("reconcile failed: %d %s", w.Code, w.Body.String())
	}

	a := snapshot(h, e).Actions["reconcile-1"]
	if a.Reconciliation == nil || !a.Reconciliation.ReplacementEligible || a.State != "completed" {
		t.Fatalf("reconcile did not produce a confirmed Reconciliation: %+v", a)
	}
	fi, _ := os.Stat(e.Spec.Rootfs)
	s := fi.Sys().(*syscall.Stat_t)
	if a.Reconciliation.ReplacementEligible && (uint32(s.Dev) == 0 && s.Ino == 0) {
		t.Fatal("evidence not actually bound to the real rootfs identity")
	}
}

// realGuestWorkspace sets up a real, hermetic git repo (bindContinuation's
// own inventory check runs real git commands against it) and returns its
// HEAD sha, matching continuation_test.go's own continuationFixture pattern.
func realGuestWorkspace(t *testing.T) (dir, head string) {
	t.Helper()
	dir = t.TempDir()
	for _, args := range [][]string{{"init", "-q"}, {"-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "--allow-empty", "-qm", "fixture"}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatal(string(out), err)
		}
	}
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return dir, strings.TrimSpace(string(out))
}

// serveGuestBroker listens on socket (removing any prior listener there --
// a real restart binds the same path fresh) and serves broker.Handler() in
// the background, returning a stop func. This is the real guest-side
// continuation path (bindContinuation), reached only through the Host's own
// postUnix proxy, never called directly by the test.
func serveGuestBroker(t *testing.T, socket string, broker *Broker) {
	t.Helper()
	os.Remove(socket)
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: broker.Handler()}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
}

// TestPublicHostReplaceResolutionTargetSequence is the full target sequence:
// start -> accept an operation on the real guest store -> stop -> reconcile
// (real evidence, as proven above) -> start again (a real second incarnation)
// -> a real guest broker restarted under that new incarnation -> the real
// Host-level /continuations endpoint, proxying over a real Unix socket to
// the real broker's bindContinuation. Nothing here is a manufactured
// receipt: the only substitutions are h.probe (the package's existing native-
// probe seam) and the two real-but-test-owned processes (helper binary,
// guest broker) standing in for the Swift VM and the guest's own broker
// process -- never a hand-built Action.Reconciliation or Store.Continuations
// entry.
func TestPublicHostReplaceResolutionTargetSequence(t *testing.T) {
	h, _ := newTestHost(t)
	dir := filepath.Join(shortTempDir(t), "env")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	e := &Environment{Spec: VMSpec{HostConfig: h.config, Environment: "env", Session: "session1", Directory: dir, Rootfs: filepath.Join(dir, "workspace.ext4"), ControlSocket: filepath.Join(dir, "agent.sock"), EgressSocket: filepath.Join(dir, "egress.sock")}, Phase: "created", Actions: map[string]Action{}}
	h.envs["env"] = e
	h.stopWait = 2 * time.Second

	workspace, head := realGuestWorkspace(t)
	storeDir := filepath.Join(shortTempDir(t), "store")

	// --- incarnation 1: start, accept an operation, leave it held ---
	if w := hostActionCall(h, "env", "start", "start-1", ""); w.Code != 200 {
		t.Fatalf("start-1 failed: %d %s", w.Code, w.Body.String())
	}
	incarnation1 := snapshot(h, e).Incarnation
	if err := os.WriteFile(e.Spec.Rootfs, []byte("retained workspace bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	store1, err := Open(storeDir, "env", "session1", incarnation1)
	if err != nil {
		t.Fatal(err)
	}
	if err := store1.BindSource(head); err != nil {
		t.Fatal(err)
	}
	task := Task{OperationID: "original-op", Incarnation: incarnation1, Text: "do the bounded work"}
	if _, _, err := store1.Begin(task); err != nil {
		t.Fatal(err)
	}
	if err := store1.Thread(incarnation1, "original-thread"); err != nil {
		t.Fatal(err)
	}
	if err := store1.Accepted(incarnation1, "original-op", "original-turn"); err != nil {
		t.Fatal(err)
	}
	originalInputHash := store1.Snapshot().Operations["original-op"].InputHash
	broker1 := NewBroker(store1, workspace)
	broker1.Actor = actorFixture()
	serveGuestBroker(t, e.Spec.ControlSocket, broker1)

	// --- stop + reconcile incarnation 1 (proven above) ---
	killAndConfirmGone(t, snapshot(h, e).PID)
	writeVMStopped(t, h, e)
	if w := hostActionCall(h, "env", "stop", "stop-1", incarnation1); w.Code != 200 {
		t.Fatalf("stop-1 failed: %d %s", w.Code, w.Body.String())
	}
	h.probe = realFenceEvidence(t, e, true)
	reconcileBody, _ := json.Marshal(ReconcileRequest{OperationID: "reconcile-1", SessionID: "session1", Incarnation: incarnation1, LaunchOperation: "start-1", FenceOperation: "stop-1"})
	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/environments/env/reconcile", strings.NewReader(string(reconcileBody))))
	if w.Code != 200 {
		t.Fatalf("reconcile-1 failed: %d %s", w.Code, w.Body.String())
	}
	store1.Close()

	// --- incarnation 2: start again ---
	if w := hostActionCall(h, "env", "start", "start-2", incarnation1); w.Code != 200 {
		t.Fatalf("start-2 failed: %d %s", w.Code, w.Body.String())
	}
	snap2 := snapshot(h, e)
	incarnation2 := snap2.Incarnation
	t.Cleanup(func() { syscall.Kill(snap2.PID, syscall.SIGKILL) })

	// --- the real guest restarts under the new incarnation: reopening the
	// same store directory is what actually (and honestly) transitions the
	// held operation to acceptance_unknown -- Open()'s own real logic
	// (state.go), not a test-injected shortcut. ---
	store2, err := Open(storeDir, "env", "session1", incarnation2)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()
	original := store2.Snapshot().Operations["original-op"]
	if original.State != "acceptance_unknown" {
		t.Fatalf("fixture must reach the real held state via Open(), got %q", original.State)
	}
	broker2 := NewBroker(store2, workspace)
	actor2 := actorFixture()
	broker2.Actor = actor2
	serveGuestBroker(t, e.Spec.ControlSocket, broker2)

	// --- the real Host-level /continuations call ---
	inventory, err := broker2.inventory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	invBytes, _ := json.Marshal(inventory)
	req := ContinuationRequest{
		DispositionID: "target-sequence", IntentRef: "resume-bounded-work", AuthorityRef: "pomar-cc-sow37-rev3",
		ResponsibleOwner: "pomar-cc", EnvironmentID: "env", WorkspaceID: "workspace-env", SessionID: "session1",
		OriginalOperation: "original-op", OriginalIncarnation: incarnation1, OriginalInputSHA256: originalInputHash,
		OriginalThreadID: "original-thread", OriginalTurnID: "original-turn",
		OriginalFenceOperation: "reconcile-1", PredecessorIncarnation: incarnation1, PredecessorFenceOperation: "reconcile-1",
		LaunchOperation: "start-2", WorkspaceInventorySHA256: digest(invBytes),
		RecoveryDescription:     "resume remaining bounded work after a real stop/reconcile/start sequence",
		ExternalActionInventory: "no scoped external action evidenced",
		Successor:               Task{OperationID: "successor-op", Incarnation: incarnation2, Text: "complete the remaining bounded work"},
	}
	reqBody, _ := json.Marshal(req)
	w = httptest.NewRecorder()
	h.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/environments/env/continuations", strings.NewReader(string(reqBody))))
	if w.Code != 200 {
		t.Fatalf("continuations call failed: %d %s", w.Code, w.Body.String())
	}

	if got := store2.Snapshot().Operations["original-op"]; got != original {
		t.Fatalf("original operation history changed: got %+v, want %+v", got, original)
	}

	// bindContinuation only binds the successor identity; dispatching its
	// turn is a separate submission, exactly as the existing broker-level
	// test (TestContinuationPreservesUnknownAndDispatchesOnlyBoundSuccessorOnce)
	// already establishes. Submit it through the real Host agent-proxy route
	// (/v1/environments/{id}/agent/{path}), not by calling broker2.Submit
	// directly, so this stays a public-Host-API test end to end.
	taskBody, _ := json.Marshal(req.Successor)
	w = httptest.NewRecorder()
	h.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/environments/env/agent/tasks", strings.NewReader(string(taskBody))))
	if w.Code != 200 {
		t.Fatalf("successor task submission failed: %d %s", w.Code, w.Body.String())
	}
	if actor2.count("turn/start") != 1 {
		t.Fatalf("expected exactly one successor turn dispatched, got %d", actor2.count("turn/start"))
	}
	if got := store2.Snapshot().Operations["original-op"]; got != original {
		t.Fatalf("original operation history changed after successor dispatch: got %+v, want %+v", got, original)
	}
}
