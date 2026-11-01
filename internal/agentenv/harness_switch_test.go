package agentenv

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func switchFixture(t *testing.T) (*Host, *Environment) {
	h, e, _, _ := reconciliationFixture(t)
	n := true
	archive := filepath.Join(e.Spec.Directory, "codex.tar.gz")
	if err := os.WriteFile(archive, []byte("pinned-fixture-package"), 0600); err != nil {
		t.Fatal(err)
	}
	old := e.Spec.HostConfig
	old.Agent = "claude"
	old.AgentVersion = "2.1.280"
	old.Seat = "example"
	old.SeatDeclarationSHA256 = strings.Repeat("a", 64)
	old.SourceBundle = "/retained/source"
	old.SourceSHA = strings.Repeat("b", 40)
	old.Base = "/retained/base"
	old.ImageDigest = "sha256:" + strings.Repeat("c", 64)
	old.ImageRef = "image@" + old.ImageDigest
	old.CodexArchive = archive
	old.CodexArchiveSHA256 = digest([]byte("pinned-fixture-package"))
	old.CPUs = 2
	old.MemoryBytes = 4 << 30
	old.MaxLive = 2
	e.Spec.HostConfig = old
	e.Spec.Profile = "claude-seat"
	e.Phase = "stopped"
	h.config = old
	h.config.Profiles = map[string]EnvironmentProfile{
		"codex-seat":  {Agent: "codex", AgentVersion: "0.160.0", AgentArchive: archive, AgentArchiveSHA256: old.CodexArchiveSHA256, Seat: old.Seat, SeatDeclarationSHA256: strings.Repeat("d", 64), SourceBundle: old.SourceBundle, SourceSHA: old.SourceSHA, Base: old.Base, ImageRef: old.ImageRef, ImageDigest: old.ImageDigest, SeatLaunch: &SeatLaunch{Sandbox: "workspace-write", Approvals: "never", NetworkAccess: &n, Model: "fixture-model", Effort: "high", CWD: "/work"}},
		"claude-seat": {Agent: "claude", AgentVersion: "2.1.280", AgentArchive: archive, AgentArchiveSHA256: old.CodexArchiveSHA256, Seat: old.Seat, SeatDeclarationSHA256: old.SeatDeclarationSHA256, SourceBundle: old.SourceBundle, SourceSHA: old.SourceSHA, Base: old.Base, ImageRef: old.ImageRef, ImageDigest: old.ImageDigest},
	}
	b, _ := json.Marshal(e.Spec)
	os.WriteFile(filepath.Join(e.Spec.Directory, "vm-config-actor.json"), b, 0600)
	return h, e
}
func switchCall(h *Host, profile, session, inc, op string) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]string{"operation_id": op, "expected_incarnation": inc, "session_id": session, "target_profile": profile})
	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/environments/env/replace", strings.NewReader(string(b))))
	return w
}
func TestHarnessSwitchSelectionPreservesSeatAndDisk(t *testing.T) {
	h, e := switchFixture(t)
	target, receipt, err := h.prepareHarnessSwitch(e, "codex-seat", "session")
	if err != nil {
		t.Fatal(err)
	}
	before := e.Spec
	disk, _ := os.ReadFile(e.Spec.Rootfs)
	e.Actions["switch"] = Action{Kind: "replace", Expected: "actor", State: "dispatching", Switch: receipt}
	// Capture genuine fixture-backed predecessor evidence before selection.
	if _, err = h.ensurePredecessor(e); err != nil {
		t.Fatal(err)
	}
	if err = h.selectHarness(e, "switch", target); err != nil {
		t.Fatal(err)
	}
	if e.Spec.Agent != "codex" || e.Spec.Profile != "codex-seat" || e.Spec.Session != before.Session || e.Spec.Environment != before.Environment || e.Spec.Rootfs != before.Rootfs || e.Spec.Directory != before.Directory || e.Spec.Incarnation != before.Incarnation {
		t.Fatalf("seat identity or target lost: %+v", e.Spec)
	}
	got, _ := os.ReadFile(e.Spec.Rootfs)
	if string(got) != string(disk) {
		t.Fatal("retained disk changed")
	}
	b, err := os.ReadFile(filepath.Join(e.Spec.Directory, "environment.json"))
	if err != nil {
		t.Fatal(err)
	}
	var restored Environment
	if json.Unmarshal(b, &restored) != nil {
		t.Fatal("invalid journal")
	}
	if !restored.Spec.RequireRetainedDisk || restored.Actions["switch"].Switch.Phase != "selected" || restored.Spec.Agent != "codex" {
		t.Fatal("selection not durable")
	}
	// Switching back selects the original harness profile, retaining the same disk.
	back, r, err := h.prepareHarnessSwitch(&restored, "claude-seat", "session")
	if err != nil {
		t.Fatal(err)
	}
	restored.Actions["back"] = Action{Kind: "replace", Expected: "actor", State: "dispatching", Switch: r}
	if err = h.selectHarness(&restored, "back", back); err != nil {
		t.Fatal(err)
	}
	if !restored.Spec.RequireRetainedDisk || restored.Spec.Agent != "claude" || restored.Spec.Rootfs != before.Rootfs {
		t.Fatal("round-trip discarded seat")
	}
}
func TestHarnessSwitchRejectsIncompatibleTargetsBeforeStop(t *testing.T) {
	for _, mode := range []string{"session", "unknown", "same-harness", "seat", "source", "image", "launch", "archive", "transfer", "headless"} {
		t.Run(mode, func(t *testing.T) {
			h, e := switchFixture(t)
			profile, session := "codex-seat", "session"
			p := h.config.Profiles[profile]
			switch mode {
			case "session":
				session = "foreign"
			case "unknown":
				profile = "absent"
			case "same-harness":
				profile = "claude-seat"
			case "seat":
				p.Seat = "foreign"
			case "source":
				p.SourceSHA = strings.Repeat("f", 40)
			case "image":
				p.ImageDigest = "sha256:" + strings.Repeat("f", 64)
			case "launch":
				p.SeatLaunch = nil
			case "archive":
				p.AgentArchiveSHA256 = strings.Repeat("f", 64)
			case "headless":
				e.Spec.Seat = ""
			case "transfer":
				e.Phase = "exported"
			}
			if profile == "codex-seat" {
				h.config.Profiles[profile] = p
			}
			before := e.Spec
			w := switchCall(h, profile, session, "actor", "switch")
			if w.Code < 400 || e.Spec.Profile != before.Profile || e.Spec.Incarnation != "actor" {
				t.Fatalf("bad target changed seat: %d %s", w.Code, w.Body.String())
			}
			if _, ok := e.Actions["switch"]; ok {
				t.Fatal("invalid target reached dispatch")
			}
		})
	}
}
func TestHarnessSwitchRequiresConfirmedFence(t *testing.T) {
	h, e := switchFixture(t)
	e.Phase = "running"
	h.stopWait = time.Millisecond
	h.processes = processFixture{err: errors.New("process observation unavailable")}
	w := switchCall(h, "codex-seat", "session", "actor", "switch")
	if w.Code < 400 || e.Spec.Agent != "claude" || e.Spec.Incarnation != "actor" || e.Actions["switch"].Switch.Phase != "prepared" || e.Actions["switch"].State != "acceptance_unknown" {
		t.Fatalf("uncertain predecessor switched: %d %s", w.Code, w.Body.String())
	}
	// A duplicate reads the original held receipt without dispatching again.
	h.stopWait = time.Hour
	w = switchCall(h, "codex-seat", "session", "actor", "switch")
	if w.Code != 200 || e.Actions["switch"].State != "acceptance_unknown" {
		t.Fatal("held retry changed outcome")
	}
}
func TestHarnessSwitchReplayBindsTargetAndSession(t *testing.T) {
	h, e := switchFixture(t)
	_, r, err := h.prepareHarnessSwitch(e, "codex-seat", "session")
	if err != nil {
		t.Fatal(err)
	}
	e.Actions["switch"] = Action{Kind: "replace", Expected: "actor", State: "completed", Switch: r}
	for _, v := range [][2]string{{"claude-seat", "session"}, {"codex-seat", "foreign"}, {"", ""}} {
		if w := switchCall(h, v[0], v[1], "actor", "switch"); w.Code < 400 {
			t.Fatal("operation ID reused against different request")
		}
	}
	// Replays must not depend on the target profile still existing.
	delete(h.config.Profiles, "codex-seat")
	if w := switchCall(h, "codex-seat", "session", "actor", "switch"); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
}
func TestHarnessSwitchProbeFailureRetainsOriginalSelection(t *testing.T) {
	h, e := switchFixture(t)
	c, r, err := h.prepareHarnessSwitch(e, "codex-seat", "session")
	if err != nil {
		t.Fatal(err)
	}
	e.Actions["switch"] = Action{Kind: "replace", Expected: "actor", State: "dispatching", Switch: r}
	e.LastFence = &Fence{Incarnation: "actor", NetworkRevoked: true, AdapterAccessRevoked: true, WorkspaceWriteRevoked: true, TerminationConfirmed: true}
	h.probe = func(context.Context, FenceProbeRequest) (FenceProbeEvidence, error) {
		return FenceProbeEvidence{}, errors.New("unavailable")
	}
	if h.selectHarness(e, "switch", c) == nil || e.Spec.Agent != "claude" {
		t.Fatal("missing predecessor evidence switched harness")
	}
}

func TestHarnessSwitchPublicRouteRetainsSelectionOnLaunchFailure(t *testing.T) {
	h, e := switchFixture(t)
	if _, err := h.ensurePredecessor(e); err != nil {
		t.Fatal(err)
	}
	e.Spec.EgressSocket = filepath.Join(e.Spec.Directory, "occupied")
	if err := os.WriteFile(e.Spec.EgressSocket, []byte("occupied"), 0600); err != nil {
		t.Fatal(err)
	}
	w := switchCall(h, "codex-seat", "session", "actor", "switch")
	if w.Code < 400 || e.Spec.Agent != "codex" || e.Spec.Profile != "codex-seat" || e.Spec.Incarnation == "actor" || e.Actions["switch"].Switch.Phase != "selected" || e.Actions["switch"].State != "acceptance_unknown" {
		t.Fatalf("failed launch lost switch state: %d %s", w.Code, w.Body.String())
	}
	incarnation := e.Spec.Incarnation
	var retained Environment
	b, err := os.ReadFile(filepath.Join(e.Spec.Directory, "environment.json"))
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(b, &retained) != nil || retained.Spec.Agent != "codex" {
		t.Fatal("selected target lost on reload")
	}
	// Replay after a host reload and changed/removed owner configuration is read-only.
	h.envs["env"] = &retained
	delete(h.config.Profiles, "codex-seat")
	w = switchCall(h, "codex-seat", "session", "actor", "switch")
	if w.Code != 200 || retained.Spec.Incarnation != incarnation || retained.Actions["switch"].State != "acceptance_unknown" {
		t.Fatal("retry redispatched or concealed hold")
	}
}

func TestHarnessSwitchSelectionWriteFailurePreventsLaunch(t *testing.T) {
	h, e := switchFixture(t)
	c, r, err := h.prepareHarnessSwitch(e, "codex-seat", "session")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.ensurePredecessor(e); err != nil {
		t.Fatal(err)
	}
	e.Actions["switch"] = Action{Kind: "replace", Expected: "actor", State: "dispatching", Switch: r}
	journal := filepath.Join(e.Spec.Directory, "environment.json")
	if err = os.Remove(journal); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(journal, 0700); err != nil {
		t.Fatal(err)
	}
	if h.selectHarness(e, "switch", c) == nil || h.fatal == nil {
		t.Fatal("write failure did not latch")
	}
	if h.start(e) == nil || e.Spec.Incarnation != "actor" {
		t.Fatal("launched despite missing durable selection")
	}
}

func TestHarnessSwitchRejectsProviderNativeContinuation(t *testing.T) {
	store, binding, _ := continuationFixture(t)
	defer store.Close()
	req := binding.Request
	h := &Host{envs: map[string]*Environment{req.EnvironmentID: {Spec: VMSpec{Environment: req.EnvironmentID, Session: req.SessionID, Incarnation: req.Successor.Incarnation}, Phase: "running", Actions: map[string]Action{
		req.OriginalFenceOperation:    {Kind: "reconcile", State: "completed", Reconciliation: &binding.OriginalFence},
		req.PredecessorFenceOperation: {Kind: "reconcile", State: "completed", Reconciliation: &binding.PredecessorFence},
		req.LaunchOperation:           {Kind: "replace", State: "completed", Expected: req.PredecessorIncarnation, ResultingIncarnation: req.Successor.Incarnation, Switch: &HarnessSwitch{FromAgent: "claude", TargetAgent: "codex"}},
	}}}}
	b, _ := json.Marshal(req)
	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/environments/"+req.EnvironmentID+"/continuations", strings.NewReader(string(b))))
	if w.Code != 409 || !strings.Contains(w.Body.String(), "cannot cross harness providers") {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestHarnessSwitchSelectedPinsCannotChangeOnRestart(t *testing.T) {
	h, e := switchFixture(t)
	c, r, err := h.prepareHarnessSwitch(e, "codex-seat", "session")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.ensurePredecessor(e); err != nil {
		t.Fatal(err)
	}
	e.Actions["switch"] = Action{Kind: "replace", Expected: "actor", State: "dispatching", Switch: r}
	if err = h.selectHarness(e, "switch", c); err != nil {
		t.Fatal(err)
	}
	p := h.config.Profiles["codex-seat"]
	p.AgentArchiveSHA256 = strings.Repeat("f", 64)
	h.config.Profiles["codex-seat"] = p
	if err = h.start(e); err == nil || !strings.Contains(err.Error(), "selected harness profile changed") || e.Spec.Incarnation != "actor" {
		t.Fatal("changed selection launched", err)
	}
}

func TestRetainedReseatKeepsDiskAndRequiresItOnNextBoot(t *testing.T) {
	h, e := switchFixture(t)
	before := e.Spec
	if _, err := h.ensurePredecessor(e); err != nil {
		t.Fatal(err)
	}
	e.Spec.EgressSocket = filepath.Join(e.Spec.Directory, "occupied")
	os.WriteFile(e.Spec.EgressSocket, []byte("occupied"), 0600)
	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/environments/env/replace", strings.NewReader(`{"operation_id":"reseat","expected_incarnation":"actor"}`)))
	if w.Code < 400 || !e.Spec.RequireRetainedDisk || e.Spec.Rootfs != before.Rootfs || e.Spec.Session != before.Session || e.Spec.Agent != before.Agent || e.Spec.Incarnation == before.Incarnation {
		t.Fatal(w.Code, e.Spec)
	}
	b, err := os.ReadFile(e.Spec.Rootfs)
	if err != nil || string(b) != "retained" {
		t.Fatal("disk changed", err)
	}
	data, err := os.ReadFile(filepath.Join(e.Spec.Directory, "environment.json"))
	if err != nil {
		t.Fatal(err)
	}
	var restored Environment
	if json.Unmarshal(data, &restored) != nil || !restored.Spec.RequireRetainedDisk {
		t.Fatal("disk requirement not durable")
	}
}

func legacyDestinationFixture() HostConfig {
	network := true
	launch := &SeatLaunch{Sandbox: "workspace-write", Approvals: "never", NetworkAccess: &network, Model: "fixture-model", Effort: "medium", CWD: "/work"}
	p := EnvironmentProfile{Base: "/owner/base.ext4", ImageRef: "registry.example/image@sha256:" + strings.Repeat("b", 64), ImageDigest: "sha256:" + strings.Repeat("b", 64), SourceBundle: "/owner/source.bundle", SourceSHA: strings.Repeat("a", 40), Seat: "legacy-seat", SeatDeclarationSHA256: strings.Repeat("c", 64), SeatLaunch: launch}
	return HostConfig{Root: "/owner", Agent: "codex", AgentVersion: "0.160.0", CodexArchive: "/owner/agent.tar", CodexArchiveSHA256: strings.Repeat("d", 64), Seat: "legacy-seat", SeatDeclarationSHA256: strings.Repeat("c", 64), SeatLaunch: launch, AllowedHosts: []string{"api.example"}, Profiles: map[string]EnvironmentProfile{"legacy": p}}
}

// Expected digests were exported by the actual untouched pre-Destination
// 06bcf6b source under a virtual test overlay, not recomputed as expectations.
func TestDestinationBindingKeepsPinnedLegacyHash(t *testing.T) {
	c := legacyDestinationFixture()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	const wantJSON = "9ddbc9d4811691e30bbf88af4cb4a423da74049548c36eaecda85f797ce8021c"
	const wantBinding = "75d8baf1af6537ebcf49c9903e357d56b1999c43390aea61cd74a83d5b4b1f2b"
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != wantJSON {
		t.Fatalf("legacy profile/config JSON changed: %s", got)
	}
	if got := harnessBinding(c); got != wantBinding {
		t.Fatalf("legacy journal binding changed: %s", got)
	}
	c.SourceDestination = "code/legacy-repo"
	if harnessBinding(c) == wantBinding {
		t.Fatal("destination missing from journal binding")
	}
	other := c
	other.SourceDestination = "code/another-repo"
	if harnessBinding(c) == harnessBinding(other) {
		t.Fatal("retargeted destination preserved launch identity")
	}
}
