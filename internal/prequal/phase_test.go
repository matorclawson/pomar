package prequal

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func fixture(t *testing.T) (string, Plan) {
	t.Helper()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	a := Artifact{Path: filepath.Join(dir, "public-artifact"), SHA256: strings.Repeat("a", 64)}
	p := Plan{RegistrationOperation: "original-register", RegistrationID: "original-registration", Schema: PlanSchema, Operation: "original", Seat: "d1-disposable", Environment: "d1-env", Session: "d1-session", Incarnation: "d1-incarnation", DeclarationSHA256: a.SHA256, CatalogueSHA256: a.SHA256, ImageSHA256: a.SHA256, SourceCommit: strings.Repeat("b", 40), AgentArchive: a, CPUs: 1, MemoryGiB: 1, DiskGiB: 4, Deadline: time.Now().Add(time.Minute), ProbeCommit: ProbeCommit, Probe: Artifact{a.Path, ProbeSHA256}, ProbePlan: a, Driver: a, HostControlsSHA256: a.SHA256}
	return dir, p
}

type registryFake struct {
	calls, retires int
	edit           func(*Registration)
	fail           bool
}

func (r *registryFake) ClaimFreshRegistration(_ context.Context, p Plan) (Registration, error) {
	r.calls++
	if r.fail {
		return Registration{}, errors.New("registrar uncertain")
	}
	v := Registration{RegistrationOperation: p.RegistrationOperation, Seat: p.Seat, Kind: "disposable", Operation: p.Operation, RowID: "actual-row", RegistrationID: "original-registration", RowSHA256: strings.Repeat("a", 64), HistorySHA256: strings.Repeat("b", 64), Preimage: "absent"}
	if r.edit != nil {
		r.edit(&v)
	}
	return v, nil
}
func (r *registryFake) Retire(_ context.Context, v Registration) (Retirement, error) {
	r.retires++
	return Retirement{v.RowID, v.RegistrationID, strings.Repeat("c", 64)}, nil
}

// Recording fake: fails on any broker/supervisor/model exec. This is a test
// backend, not a concrete registry/VM implementation or native evidence.
type vmFake struct {
	plan                                            Plan
	badProbeReceipt                                 bool
	calls                                           []Command
	boot, stops                                     int
	badStop, failProbe, agentAtDrain, terminalFault bool
	listings                                        int
	parent                                          string
	operation                                       string
}

func (v *vmFake) Boot(_ context.Context, p Plan, _ Registration) (string, error) {
	v.boot++
	v.plan = p
	v.operation = p.Operation
	if v.terminalFault {
		if e := os.WriteFile(filepath.Join(v.parent, p.Operation, "terminal.json"), []byte("preexisting"), 0600); e != nil {
			return "", e
		}
	}
	return "owned-scope", nil
}
func (v *vmFake) Exec(_ context.Context, c Command) (Output, error) {
	v.calls = append(v.calls, c)
	if c.Program != "/pomar/isolation-probe" && c.Program != "/pomar/d1-driver" && c.Program != "/bin/ps" {
		return Output{}, errors.New("FORBIDDEN MODEL/BROKER/SUPERVISOR EXEC")
	}
	if c.Kind == "guest-process-list" {
		v.listings++
		if v.agentAtDrain && v.listings >= 2 {
			return Output{Bytes: []byte("4 1000 /opt/codex\n")}, nil
		}
		return Output{Bytes: []byte("1 0 /bin/sleep\n2 0 /bin/ps\n")}, nil
	}
	if v.failProbe && c.Kind == "isolation" {
		return Output{Exit: 1, Bytes: []byte("denial failed")}, nil
	}
	if c.Kind == "isolation" {
		if v.badProbeReceipt {
			return Output{Bytes: []byte(`{}`)}, nil
		}
		return Output{Bytes: probeFixture(v.plan)}, nil
	}
	return Output{Bytes: []byte(`{"observation":"simulated only"}`)}, nil
}
func (v *vmFake) Stop(_ context.Context, scope string) (Drain, error) {
	v.stops++
	return Drain{scope, true, !v.badStop, []int{}}, nil
}
func (v *vmFake) HostListing(context.Context, string) ([]byte, error) {
	return []byte("owned-scope: no live processes; TEST ONLY\n"), nil
}
func simulatedVerify(Artifact) error { return nil }
func TestSuccessRecordsAllExecsAndRetiresWithoutAuthority(t *testing.T) {
	dir, p := fixture(t)
	reg := &registryFake{}
	v := &vmFake{}
	r, e := run(context.Background(), dir, p, reg, v, simulatedVerify)
	if e != nil || r.State != "observations_complete_requires_owner_join" || reg.calls != 1 || reg.retires != 1 || v.stops != 1 {
		t.Fatalf("%+v %v", r, e)
	}
	if r.AdmissionGranted || r.InteractiveQualified || r.Retirement == nil || len(r.HostProcessListing) == 0 || len(r.Executions) != 4 {
		t.Fatal(r)
	}
	b1, _ := json.Marshal(v.calls)
	b2, _ := json.Marshal(r.Executions)
	if string(b1) != string(b2) {
		t.Fatal("owner exec missing from receipt")
	}
	b, e := os.ReadFile(r.TerminalPath)
	if e != nil {
		t.Fatal(e)
	}
	var saved Result
	if json.Unmarshal(b, &saved) != nil || saved.State != r.State || saved.Registration.RowID != "actual-row" || saved.Retirement.RegistrationID != "original-registration" {
		t.Fatal(string(b))
	}
	entries, e := os.ReadDir(filepath.Dir(r.TerminalPath))
	if e != nil {
		t.Fatal(e)
	}
	if len(entries) < 10 {
		t.Fatal("missing durable original event trail")
	}
	_, e = run(context.Background(), dir, p, reg, v, simulatedVerify)
	if !errors.Is(e, ErrOriginalExists) || reg.calls != 1 {
		t.Fatal("repeated original executed", e, reg.calls)
	}
}
func TestFreshDisposableRegistryBoundary(t *testing.T) {
	for _, change := range []string{"host", "history-session", "history-mail", "existing-name", "different-operation", "missing-evidence", "unknown-effect"} {
		t.Run(change, func(t *testing.T) {
			dir, p := fixture(t)
			reg := &registryFake{edit: func(r *Registration) {
				switch change {
				case "host":
					r.Kind = "host-seat"
				case "history-session":
					r.EarlierSessions = 1
				case "history-mail":
					r.EarlierMail = 1
				case "existing-name":
					r.Preimage = "existing"
				case "different-operation":
					r.Operation = "other"
				case "missing-evidence":
					r.HistorySHA256 = ""
				}
			}, fail: change == "unknown-effect"}
			v := &vmFake{}
			r, e := run(context.Background(), dir, p, reg, v, simulatedVerify)
			if e == nil || v.boot != 0 || reg.retires != 0 || r.State != "unknown_retained" {
				t.Fatal(r, e, v.boot, reg.retires)
			}
		})
	}
}
func TestFailuresRetainOriginalAndPositiveCleanup(t *testing.T) {
	for _, which := range []string{"probe-failed", "unknown-stop", "agent-at-drain", "terminal-write-fault"} {
		t.Run(which, func(t *testing.T) {
			dir, p := fixture(t)
			reg := &registryFake{}
			v := &vmFake{failProbe: which == "probe-failed", badStop: which == "unknown-stop", agentAtDrain: which == "agent-at-drain", terminalFault: which == "terminal-write-fault", parent: dir}
			r, e := run(context.Background(), dir, p, reg, v, simulatedVerify)
			if e == nil || v.stops != 1 || r.AdmissionGranted || r.InteractiveQualified {
				t.Fatal(r, e)
			}
			want := "failed_stopped"
			if which == "unknown-stop" || which == "terminal-write-fault" {
				want = "unknown_retained"
			}
			if r.State != want {
				t.Fatal(r.State, want, e)
			}
			if which == "unknown-stop" && reg.retires != 0 {
				t.Fatal("unknown scope lost registry hold")
			}
			if which == "terminal-write-fault" {
				b, _ := os.ReadFile(r.TerminalPath)
				if string(b) != "preexisting" {
					t.Fatal("overwrote uncertain terminal")
				}
			}
			if _, e = os.Stat(filepath.Join(dir, p.Operation, "plan.json")); e != nil {
				t.Fatal("failure evidence removed", e)
			}
		})
	}
}
func TestClosedExecutorRejectsModelBeforeBackend(t *testing.T) {
	dir, p := fixture(t)
	j, e := openJournal(dir, p.Operation)
	if e != nil {
		t.Fatal(e)
	}
	v := &vmFake{}
	r := Result{}
	for _, program := range []string{"/pomar/agent-broker", "/pomar/agent-guest", "/bin/seat-supervisor", "/opt/codex", "/opt/claude", "/bin/sh"} {
		if _, e = j.execute(context.Background(), v, Command{"isolation", program, nil, 1000}, &r); e == nil {
			t.Fatal("forbidden exec admitted", program)
		}
	}
	if len(v.calls) != 0 {
		t.Fatal("forbidden reached backend")
	}
}
func TestPlanPinsSchemaResourcesAndDeadline(t *testing.T) {
	_, p := fixture(t)
	if e := p.Validate(time.Now()); e != nil {
		t.Fatal(e)
	}
	for _, change := range []string{"schema", "old-commit", "old-binary", "missing-binary", "past", "long", "resource", "declaration"} {
		q := p
		switch change {
		case "schema":
			q.Schema = ResultSchema
		case "old-commit":
			q.ProbeCommit = strings.Repeat("a", 40)
		case "old-binary":
			q.Probe.SHA256 = "4ae3fc6794afdbbe08e0f0a4b0176024c34264857d4358355fd9933974e7a5c8"
		case "missing-binary":
			q.Probe.SHA256 = ""
		case "past":
			q.Deadline = time.Now().Add(-time.Second)
		case "long":
			q.Deadline = time.Now().Add(time.Hour)
		case "resource":
			q.CPUs = 5
		case "declaration":
			q.DeclarationSHA256 = ""
		}
		if q.Validate(time.Now()) == nil {
			t.Fatal("invalid plan accepted", change)
		}
	}
}
func TestArtifactCustodyRefusesLinksFIFOAndChangedPin(t *testing.T) {
	dir, _ := fixture(t)
	f := filepath.Join(dir, "public")
	if e := os.WriteFile(f, []byte("public"), 0600); e != nil {
		t.Fatal(e)
	}
	a := Artifact{f, fmt.Sprintf("%x", sha256.Sum256([]byte("public")))}
	if verifyArtifact(a) != nil {
		t.Fatal("valid public artifact refused")
	}
	a.SHA256 = strings.Repeat("0", 64)
	if verifyArtifact(a) == nil {
		t.Fatal("wrong digest accepted")
	}
	link := f + "-link"
	os.Symlink(f, link)
	if verifyArtifact(Artifact{link, a.SHA256}) == nil {
		t.Fatal("symlink accepted")
	}
	fifo := f + "-fifo"
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	if verifyArtifact(Artifact{fifo, a.SHA256}) == nil {
		t.Fatal("FIFO accepted")
	}
}
func TestNoDefaultAdaptersAndNoUnpinnedNativeStart(t *testing.T) {
	dir, p := fixture(t)
	if _, e := Run(context.Background(), dir, p, nil, nil); e == nil {
		t.Fatal("missing owner adapters accepted")
	}
	reg := &registryFake{}
	v := &vmFake{}
	if _, e := Run(context.Background(), dir, p, reg, v); e == nil || reg.calls != 0 || v.boot != 0 {
		t.Fatal("missing pinned public artifacts reached effects", e)
	}
}

func TestCancelledOriginalDoesNotAllocateOrRegister(t *testing.T) {
	dir, p := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reg := &registryFake{}
	v := &vmFake{}
	if _, err := run(ctx, dir, p, reg, v, simulatedVerify); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, p.Operation)); !os.IsNotExist(err) || reg.calls != 0 || v.boot != 0 {
		t.Fatal("cancelled original effected", err)
	}
}

func probeFixture(p Plan) []byte {
	m := []byte("synthetic mount fixture\n")
	h := fmt.Sprintf("%x", sha256.Sum256(m))
	who := map[string]any{"uid": 1000, "euid": 1000, "gid": 1000, "egid": 1000, "groups": []int{1000}}
	mount := map[string]any{"bytes": len(m), "sha256": h, "base64": base64.StdEncoding.EncodeToString(m)}
	raw, _ := json.Marshal(map[string]any{"schema": "pomar.isolation-probe/v2", "state": "observations_complete_requires_owner_join", "plan_sha256": p.ProbePlan.SHA256, "environment": p.Environment, "session": p.Session, "incarnation": p.Incarnation, "admission_granted": false, "native_isolation_accepted": false, "observed_before": who, "observed_after": who, "mountinfo_before": mount, "mountinfo_after": mount, "observations": []any{map[string]any{"state": "refused_requires_owner_join", "positive_before": true, "positive_after": true, "errno_class": "ENOENT", "owner_evidence_sha256": p.HostControlsSHA256}}})
	return raw
}
func TestProbeReceiptBindingAndNoSelfAcceptance(t *testing.T) {
	_, p := fixture(t)
	raw := probeFixture(p)
	if e := probeObservation(raw, p); e != nil {
		t.Fatal(e)
	}
	for _, change := range []string{"identity", "plan", "admission", "mount", "missing"} {
		var v map[string]any
		json.Unmarshal(raw, &v)
		switch change {
		case "identity":
			v["incarnation"] = "other"
		case "plan":
			v["plan_sha256"] = strings.Repeat("0", 64)
		case "admission":
			v["admission_granted"] = true
		case "mount":
			v["mountinfo_after"].(map[string]any)["sha256"] = strings.Repeat("0", 64)
		case "missing":
			delete(v, "observed_before")
		}
		b, _ := json.Marshal(v)
		if probeObservation(b, p) == nil {
			t.Fatal("false probe accepted", change)
		}
	}
	dir, p := fixture(t)
	reg := &registryFake{}
	vm := &vmFake{badProbeReceipt: true}
	r, e := run(context.Background(), dir, p, reg, vm, simulatedVerify)
	if e == nil || r.State != "failed_stopped" || vm.stops != 1 {
		t.Fatal(r, e)
	}
}
