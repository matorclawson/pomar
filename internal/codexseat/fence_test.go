package codexseat

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func processFixture(t *testing.T, uid string) string {
	t.Helper()
	proc := t.TempDir()
	dir := filepath.Join(proc, "42")
	os.Mkdir(dir, 0700)
	os.WriteFile(filepath.Join(dir, "status"), []byte("Name:\tdev-server\nUid:\t"+strings.Repeat(uid+"\t", 4)+"\n"), 0600)
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = "S"
	fields[19] = "12345"
	os.WriteFile(filepath.Join(dir, "stat"), []byte("42 (dev-server) "+strings.Join(fields, " ")), 0600)
	return proc
}
func TestRootProcessWitnessDoesNotTrustActorFence(t *testing.T) {
	proc := processFixture(t, "1000")
	p, err := codingProcesses(proc, 1000)
	if err != nil || len(p) != 1 || p[0].PID != 42 || p[0].Command != "dev-server" || p[0].StartTicks != "12345" {
		t.Fatal(p, err)
	}
	// A coding user's unlocked/recreated old lock cannot authorize a root reset.
	s, req, archive := resetFixture(t)
	os.Remove(filepath.Join(s.StateDir, "actor.lock"))
	os.WriteFile(filepath.Join(s.StateDir, "actor.lock"), nil, 0600)
	uid := uint32(os.Getuid())
	quiescent := func() error { return noCodingProcesses(proc, 1000) }
	if _, err = s.abandonChecked(req, archive, uid, uid, quiescent); !errors.Is(err, ErrActorRunning) {
		t.Fatal("live scope reset", err)
	}
	data, _ := os.ReadFile(filepath.Join(s.StateDir, "codex-thread.json"))
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != req.RecordSHA256 {
		t.Fatal("live startup changed")
	}
	// Same root-side process observation is required before native opening/start.
	called := false
	err = s.startChecked(func() (*os.File, error) { called = true; return nil, errors.New("must not open") }, nil, quiescent)
	if !errors.Is(err, ErrActorRunning) || called {
		t.Fatal("second writer dispatched", err)
	}
}
func TestProcessObservationMissingOrMalformedIsHeld(t *testing.T) {
	proc := processFixture(t, "0")
	if err := noCodingProcesses(proc, 1000); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(proc, "42", "status"))
	if err := noCodingProcesses(proc, 1000); err == nil {
		t.Fatal("disappearing entry became idle")
	}
	os.WriteFile(filepath.Join(proc, "42", "status"), []byte("Uid: 1000 invalid 1000 1000\n"), 0600)
	if err := noCodingProcesses(proc, 1000); err == nil {
		t.Fatal("malformed UID became idle")
	}
}
func TestCodingActorReceivesNoFenceAndDropsPrivilege(t *testing.T) {
	s := fixture(t)
	f, _ := os.Open(os.DevNull)
	defer f.Close()
	cmd := s.nativeCommand("/custodian/guest", pending(s), f)
	if len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0] != f {
		t.Fatal("actor inherited a fence")
	}
	c := cmd.SysProcAttr.Credential
	if c.Uid != 1000 || c.Gid != 1000 || len(c.Groups) != 1 || c.Groups[0] != 1000 {
		t.Fatal("actor privilege not dropped", c)
	}
	if os.Geteuid() != 0 {
		if err := s.Start(); err == nil {
			t.Fatal("coding user obtained root start")
		}
	}
}
func TestResetReplayNamesNewStartingRecord(t *testing.T) {
	s, req, archive := resetFixture(t)
	uid := uint32(os.Getuid())
	first, err := s.abandonStart(req, archive, uid, uid)
	if err != nil {
		t.Fatal(err)
	}
	next := pending(s)
	next.StartupNonce = "second-intent"
	s.write(next)
	replay, err := s.abandonStart(req, archive, uid, uid)
	if err != nil {
		t.Fatal(err)
	}
	if replay.CurrentState != "starting" || replay.CurrentSHA256 == "" || replay.CurrentSHA256 == req.RecordSHA256 || replay.PriorSHA256 != first.PriorSHA256 {
		t.Fatal("replay concealed current startup", replay)
	}
	if _, err := os.Stat(filepath.Join(s.StateDir, "codex-thread.json")); err != nil {
		t.Fatal("replay cleared newer startup")
	}
}
func TestSnapshotHashUsesParsedBytes(t *testing.T) {
	s, req, _ := resetFixture(t)
	r, data, info, err := s.readSnapshot(uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if r.State != "starting" || info == nil || hex.EncodeToString(sum[:]) != req.RecordSHA256 {
		t.Fatal("snapshot mismatch")
	}
	// A later path replacement cannot change either the parsed state or digest.
	next := pending(s)
	next.State = "bound"
	next.Thread = id1
	s.write(next)
	if r.State != "starting" || hex.EncodeToString(sum[:]) != req.RecordSHA256 {
		t.Fatal("snapshot followed replacement")
	}
}
