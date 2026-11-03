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
	p := Plan{MailMapping: MailMapping{HostPath: filepath.Join(dir, "mail.sock"), GuestPath: "/run/pomar/mail.sock", Direction: "into", Mode: 0600, Seat: "d1-disposable", DeniedPairsSHA256: a.SHA256}, RegistryStore: filepath.Join(dir, "registry"), RegisteredAt: time.Now().UTC().Format(time.RFC3339Nano), RegistryRecordSHA256: strings.Repeat("c", 64), Schema: PlanSchema, Operation: "original", Seat: "d1-disposable", Environment: "d1-env", Session: "d1-session", Incarnation: "d1-incarnation", DeclarationSHA256: a.SHA256, CatalogueSHA256: a.SHA256, ImageSHA256: a.SHA256, SourceCommit: strings.Repeat("b", 40), AgentArchive: a, CPUs: 1, MemoryGiB: 1, DiskGiB: 4, Deadline: time.Now().Add(time.Minute), ProbeCommit: ProbeCommit, Probe: Artifact{a.Path, ProbeSHA256}, ProbePlan: a, Driver: a, MailShim: a, HostControlsSHA256: a.SHA256}
	return dir, p
}

type registryFake struct {
	approval       Binding
	retireFault    bool
	calls, retires int
	edit           func(*Registration)
	fail           bool
}

func bindingFor(p Plan) Binding {
	return Binding{p.Seat, p.RegistryStore, p.RegisteredAt, p.RegistryRecordSHA256}
}
func (r *registryFake) ApprovedBinding(context.Context) (Binding, error) { return r.approval, nil }
func (r *registryFake) ClaimFreshRegistration(_ context.Context, p Plan) (Registration, error) {
	r.calls++
	if r.fail {
		return Registration{}, errors.New("registrar uncertain")
	}
	v := Registration{Instance: p.Seat, Store: p.RegistryStore, RegisteredAt: p.RegisteredAt, RecordSHA256: p.RegistryRecordSHA256, Runtime: "pre-model-observer", WriteAuthority: "none", Status: "active", Operation: p.Operation, HistorySHA256: strings.Repeat("b", 64), Preimage: "absent"}
	if r.edit != nil {
		r.edit(&v)
	}
	return v, nil
}
func (r *registryFake) Retire(_ context.Context, v Registration) (Retirement, error) {
	r.retires++
	rr := Retirement{Instance: v.Instance, Store: v.Store, RegisteredAt: v.RegisteredAt, Operation: v.Operation, Status: "retired", CommandTerminalSHA256: strings.Repeat("c", 64), ReadbackSHA256: strings.Repeat("d", 64), Teardown: "confirmed"}
	if r.retireFault {
		rr.TerminalExit = 1
		rr.Teardown = "unknown"
		return rr, errors.New("status committed before teardown fault")
	}
	return rr, nil
}

// Recording fake: fails on any broker/supervisor/model exec. This is a test
// backend, not a concrete registry/VM implementation or native evidence.
type vmFake struct {
	hiddenHostAgent                                 bool
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
func (v *vmFake) StartTransport(_ context.Context, scope, operation string, c Command) (Transport, error) {
	return Transport{ScopeID: scope, Operation: operation, Handle: "actual-test-process", Command: c, Ready: true}, nil
}
func (v *vmFake) Exec(_ context.Context, c Command) (Output, error) {
	v.calls = append(v.calls, c)
	if c.Program != "/pomar/isolation-probe" && c.Program != "/pomar/d1-driver" && c.Program != "/bin/ps" {
		return Output{}, errors.New("FORBIDDEN MODEL/BROKER/SUPERVISOR EXEC")
	}
	if c.Kind == "owner-guest-inventory" {
		rows := []ProcessRow{{PID: 1, UID: 0, Exe: "/bin/sleep"}, {PID: 2, UID: 0, Exe: "/bin/ps"}, {PID: 3, UID: 0, Exe: "/pomar/shim", Args: mailShimArgs()}, {PID: 4, UID: 0, Exe: "/pomar/d1-driver", Args: append([]string{"/pomar/d1-driver"}, collectorCommand("owned-scope").Args...)}}
		if v.hiddenHostAgent {
			rows = append(rows, ProcessRow{PID: 9, UID: 1000, Exe: "/usr/bin/node"})
		}
		raw, _ := json.Marshal(ProcessSnapshot{ScopeID: "owned-scope", Kind: OwnerGuestInventoryKind, Rows: rows})
		return Output{Bytes: raw}, nil
	}
	if c.Kind == "guest-process-list" {
		v.listings++
		if v.agentAtDrain && v.listings >= 2 {
			return Output{Bytes: []byte("4 1000 /opt/codex\n")}, nil
		}
		return Output{Bytes: []byte("1 0 /bin/sleep\n2 0 /bin/ps\n3 0 /pomar/shim\n")}, nil
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
func (v *vmFake) HostListing(context.Context, string) (ProcessSnapshot, error) {
	if v.stops > 0 {
		return ProcessSnapshot{ScopeID: "owned-scope", Kind: HostAfterStopKind, Rows: []ProcessRow{}}, nil
	}
	return ProcessSnapshot{}, errors.New("host view cannot substitute for pre-stop in-guest inventory")
}

func simulatedVerify(Artifact) error { return nil }
func TestSuccessRecordsAllExecsAndRetiresWithoutAuthority(t *testing.T) {
	dir, p := fixture(t)
	reg := &registryFake{approval: bindingFor(p)}
	v := &vmFake{}
	r, e := run(context.Background(), dir, p, reg, v, simulatedVerify)
	if e != nil || r.State != "observations_complete_requires_owner_join" || reg.calls != 1 || reg.retires != 1 || v.stops != 1 {
		t.Fatalf("%+v %v", r, e)
	}
	if r.AdmissionGranted || r.InteractiveQualified || r.Retirement == nil || r.HostBefore == nil || r.HostAfter == nil || len(r.Executions) != 5 {
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
	if json.Unmarshal(b, &saved) != nil || saved.State != r.State || saved.Registration.Store != p.RegistryStore || saved.Retirement.RegisteredAt != p.RegisteredAt {
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
			reg := &registryFake{approval: bindingFor(p), edit: func(r *Registration) {
				switch change {
				case "host":
					r.Runtime = "host-seat"
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
			reg := &registryFake{approval: bindingFor(p)}
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
	r := Result{Plan: p, ScopeID: "owned-scope"}
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
	reg := &registryFake{approval: bindingFor(p)}
	v := &vmFake{}
	if _, e := Run(context.Background(), dir, p, reg, v); e == nil || reg.calls != 0 || v.boot != 0 {
		t.Fatal("missing pinned public artifacts reached effects", e)
	}
}

func TestCancelledOriginalDoesNotAllocateOrRegister(t *testing.T) {
	dir, p := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reg := &registryFake{approval: bindingFor(p)}
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
	reg := &registryFake{approval: bindingFor(p)}
	vm := &vmFake{badProbeReceipt: true}
	r, e := run(context.Background(), dir, p, reg, vm, simulatedVerify)
	if e == nil || r.State != "failed_stopped" || vm.stops != 1 {
		t.Fatal(r, e)
	}
}

func TestSplitRetirementRetainsCommittedRowAndTeardownFailure(t *testing.T) {
	dir, p := fixture(t)
	reg := &registryFake{approval: bindingFor(p), retireFault: true}
	vm := &vmFake{}
	r, e := run(context.Background(), dir, p, reg, vm, simulatedVerify)
	if e == nil || r.State != "unknown_retained" || r.Retirement == nil || r.Retirement.Status != "retired" || r.Retirement.TerminalExit != 1 || r.Retirement.Teardown != "unknown" || vm.stops != 1 || reg.retires != 1 {
		t.Fatal(r, e)
	}
	if _, e = run(context.Background(), dir, p, reg, vm, simulatedVerify); !errors.Is(e, ErrOriginalExists) || reg.retires != 1 {
		t.Fatal("split retirement retried", e)
	}
}
func TestActualRegistrationBindingAndAuthorityDrift(t *testing.T) {
	for _, change := range []string{"store", "registered-at", "record-sha", "authority", "status"} {
		t.Run(change, func(t *testing.T) {
			dir, p := fixture(t)
			reg := &registryFake{approval: bindingFor(p), edit: func(r *Registration) {
				switch change {
				case "store":
					r.Store += "-changed"
				case "registered-at":
					r.RegisteredAt = "2000-01-01T00:00:00Z"
				case "record-sha":
					r.RecordSHA256 = strings.Repeat("0", 64)
				case "authority":
					r.WriteAuthority = "write"
				case "status":
					r.Status = "retired"
				}
			}}
			vm := &vmFake{}
			r, e := run(context.Background(), dir, p, reg, vm, simulatedVerify)
			if e == nil || vm.boot != 0 || r.State != "unknown_retained" {
				t.Fatal(r, e)
			}
		})
	}
}

func TestSoleApprovedRowCannotBeChangedByPlan(t *testing.T) {
	dir, p := fixture(t)
	reg := &registryFake{approval: bindingFor(p)}
	vm := &vmFake{}
	q := p
	q.Seat = "another-fresh-seat"
	if _, e := run(context.Background(), dir, q, reg, vm, simulatedVerify); e == nil || reg.calls != 0 || vm.boot != 0 {
		t.Fatal("another row admitted", e)
	}
}
func TestClosedProcessAllowlistRejectsTruncationInterpretersAndHiddenHostRows(t *testing.T) {
	for _, exe := range []string{"/pomar/pomar-agent-gue", "/opt/pomar-agent-guest", "/usr/bin/node", "/usr/bin/python3", "/bin/sh", "/tmp/ps", "/pomar/isolation-prob"} {
		s := ProcessSnapshot{ScopeID: "owned", Kind: OwnerGuestInventoryKind, Rows: []ProcessRow{{PID: 3, UID: 1000, Exe: exe}}}
		if validateProcesses(s, "owned") == nil {
			t.Fatal("host executable accepted", exe)
		}
	}
	s := ProcessSnapshot{ScopeID: "owned", Kind: OwnerGuestInventoryKind, Rows: []ProcessRow{{PID: 1, UID: 0, Exe: "/bin/sleep"}}}
	for _, raw := range []string{"3 1000 pomar-agent-gue\n", "3 1000 /usr/bin/node agent.js\n", "3 1000 [fake-kernel]\n"} {
		if validateGuestProcesses([]byte(raw), s) == nil {
			t.Fatal("guest executable accepted", raw)
		}
	}
	dir, p := fixture(t)
	reg := &registryFake{approval: bindingFor(p)}
	vm := &vmFake{hiddenHostAgent: true}
	r, e := run(context.Background(), dir, p, reg, vm, simulatedVerify)
	if e == nil || r.State != "failed_stopped" || r.HostBefore == nil || len(r.HostBefore.Rows) != 5 {
		t.Fatal("host-only agent omitted by guest accepted", r, e)
	}
}

type oversizedVM struct{ vmFake }

func (v *oversizedVM) Exec(context.Context, Command) (Output, error) {
	return Output{Bytes: make([]byte, (1<<20)+1)}, nil
}
func TestOversizedExecIsDurablyRecordedAsFailure(t *testing.T) {
	dir, p := fixture(t)
	j, e := openJournal(dir, p.Operation)
	if e != nil {
		t.Fatal(e)
	}
	r := Result{Plan: p, ScopeID: "owned-scope"}
	v := &oversizedVM{}
	if _, e = j.execute(context.Background(), v, Command{"isolation", "/pomar/isolation-probe", []string{"-plan", "/pomar/probe-plan.json", "-plan-sha256", p.ProbePlan.SHA256, "-deadline", time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339)}, 1000}, &r); e == nil {
		t.Fatal("oversize accepted")
	}
	raw, e := os.ReadFile(filepath.Join(j.dir, eventName(2)))
	if e != nil {
		t.Fatal("exec-after missing", e)
	}
	var event struct {
		Stage         string
		Failed        bool
		OutputLimit   bool
		ReportedBytes int
		Output        Output
	}
	if json.Unmarshal(raw, &event) != nil || event.Stage != "exec-after" || !event.Failed || !event.OutputLimit || event.ReportedBytes != (1<<20)+1 || len(event.Output.Bytes) != 1<<20 {
		t.Fatal("failed bounded output not recorded")
	}
}
