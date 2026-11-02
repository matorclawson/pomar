package prequal

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type transportFaultVM struct {
	vmFake
	fault  string
	starts int
}

func (v *transportFaultVM) StartTransport(_ context.Context, scope, operation string, c Command) (Transport, error) {
	v.starts++
	x := Transport{ScopeID: scope, Operation: operation, Handle: "owned-process", Command: c, Ready: true}
	switch v.fault {
	case "unknown":
		return x, errors.New("lost start response")
	case "scope":
		x.ScopeID = "other"
	case "operation":
		x.Operation = "other"
	case "handle":
		x.Handle = ""
	case "unready":
		x.Ready = false
	case "uid":
		x.Command.UID = 1000
	case "inplace-args":
		x.Command.Args[2] = "0.0.0.0:7743"
	case "args":
		x.Command.Args = []string{"-listen", "0.0.0.0:7743"}
	}
	return x, nil
}
func TestTransportStartIsExplicitRecordedAndBound(t *testing.T) {
	for _, fault := range []string{"", "unknown", "scope", "operation", "handle", "unready", "uid", "args", "inplace-args"} {
		t.Run(fault, func(t *testing.T) {
			dir, p := fixture(t)
			reg := &registryFake{approval: bindingFor(p)}
			v := &transportFaultVM{fault: fault}
			r, e := run(context.Background(), dir, p, reg, v, simulatedVerify)
			if v.starts != 1 || r.Transport == nil || v.stops != 1 {
				t.Fatalf("start or drain missing: %d %d", v.starts, v.stops)
			}
			if fault == "" {
				if e != nil {
					t.Fatal(e)
				}
			} else if e == nil || r.State == "observations_complete_requires_owner_join" {
				t.Fatal("uncertain transport accepted")
			}
			before, after := 0, 0
			entries, err := os.ReadDir(filepath.Dir(r.TerminalPath))
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range entries {
				if !strings.HasPrefix(f.Name(), "event-") {
					continue
				}
				raw, err := os.ReadFile(filepath.Join(filepath.Dir(r.TerminalPath), f.Name()))
				if err != nil {
					t.Fatal(err)
				}
				var event struct{ Stage string }
				if err = json.Unmarshal(raw, &event); err != nil {
					t.Fatal(err)
				}
				switch event.Stage {
				case "transport-start-before":
					before++
				case "transport-start-after":
					after++
				}
			}
			if before != 1 || after != 1 {
				t.Fatalf("transport exec omitted from journal: %d/%d", before, after)
			}
			if fault != "" {
				for _, c := range v.calls {
					if c.Kind == "isolation" || c.Kind == "mail-d1" {
						t.Fatal("phase continued after bad transport")
					}
				}
			}
		})
	}
}
func TestTransportJournalCollisionPreventsEffect(t *testing.T) {
	dir, p := fixture(t)
	j, e := openJournal(dir, p.Operation)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(j.dir, eventName(1)), []byte("existing-original"), 0600); e != nil {
		t.Fatal(e)
	}
	v := &transportFaultVM{}
	r := Result{Plan: p, ScopeID: "owned-scope"}
	if j.startTransport(context.Background(), v, &r) == nil || v.starts != 0 {
		t.Fatal("effect occurred before original journal")
	}
}
func TestExactExecModesAndInfrastructureInventory(t *testing.T) {
	_, p := fixture(t)
	scope := "owned-scope"
	c := collectorCommand(scope)
	if !allowedPhaseCommand(c, p, scope) {
		t.Fatal("fixed collector refused")
	}
	c.UID = 1000
	if allowedPhaseCommand(c, p, scope) {
		t.Fatal("collector unprivileged mode accepted")
	}
	c = collectorCommand(scope)
	c.Args[3] = "other"
	if allowedPhaseCommand(c, p, scope) {
		t.Fatal("different collector scope accepted")
	}
	c = Command{"mail-d1", "/pomar/d1-driver", mailArgs(p), 1000}
	if !allowedPhaseCommand(c, p, scope) {
		t.Fatal("fixed mail refused")
	}
	c.UID = 0
	if allowedPhaseCommand(c, p, scope) {
		t.Fatal("root mail mode accepted")
	}
	good := ProcessRow{PID: 42, UID: 0, Exe: "/pomar/shim", Args: mailShimArgs()}
	if !allowedProcess(good) {
		t.Fatal("exact shim refused")
	}
	for _, mutate := range []func(*ProcessRow){func(p *ProcessRow) { p.UID = 1000 }, func(p *ProcessRow) { p.Exe = "/tmp/shim" }, func(p *ProcessRow) { p.Args[2] = "0.0.0.0:7743" }, func(p *ProcessRow) { p.Args = nil }} {
		x := good
		x.Args = append([]string(nil), good.Args...)
		mutate(&x)
		if allowedProcess(x) {
			t.Fatal("changed shim identity accepted")
		}
	}
	s := ProcessSnapshot{ScopeID: scope, Kind: OwnerGuestInventoryKind, Rows: []ProcessRow{good, {PID: 43, UID: 0, Exe: "/pomar/d1-driver", Args: append([]string{"/pomar/d1-driver"}, collectorCommand(scope).Args...)}}}
	raw, _ := json.Marshal(s)
	if _, e := parseInventory(raw, scope); e != nil {
		t.Fatal(e)
	}
	s.Kind = HostAfterStopKind
	raw, _ = json.Marshal(s)
	if _, e := parseInventory(raw, scope); e == nil {
		t.Fatal("host label substituted for in-guest inventory")
	}
	if _, e := parseInventory(append(raw, []byte(" {}")...), scope); e == nil {
		t.Fatal("extra inventory accepted")
	}
}
func TestProcReadsCompleteArgsAndRefusesArgvDrift(t *testing.T) {
	root := procFixture(t, 42, 0, "/pomar/shim", false)
	dir := filepath.Join(root, "42")
	writeProc(t, dir, "cmdline", strings.Join(mailShimArgs(), "\x00")+"\x00")
	got, e := collectProc(context.Background(), root, "owned", nil)
	if e != nil || !allowedProcess(got.Rows[0]) {
		t.Fatalf("exact argv missing: %+v %v", got, e)
	}
	if _, e := collectProc(context.Background(), root, "owned", func(int) error {
		writeProc(t, dir, "cmdline", "/pomar/shim\x00-listen\x000.0.0.0:7743\x00")
		return nil
	}); e == nil {
		t.Fatal("argv drift accepted")
	}
}

func TestNativePlanRejectsOldSchemaAndMappingDrift(t *testing.T) {
	_, p := fixture(t)
	for _, which := range []string{"old-schema", "guest-path", "direction", "mode", "seat", "host-path", "denied-pairs", "shim-pin"} {
		t.Run(which, func(t *testing.T) {
			q := p
			switch which {
			case "old-schema":
				q.Schema = "pomar.pre-model-plan/v1"
			case "guest-path":
				q.MailMapping.GuestPath = "/run/pomar/agent.sock"
			case "direction":
				q.MailMapping.Direction = "outOf"
			case "mode":
				q.MailMapping.Mode = 0666
			case "seat":
				q.MailMapping.Seat = "host-seat"
			case "host-path":
				q.MailMapping.HostPath = "relative.sock"
			case "denied-pairs":
				q.MailMapping.DeniedPairsSHA256 = ""
			case "shim-pin":
				q.MailShim.SHA256 = ""
			}
			if q.Validate(time.Now()) == nil {
				t.Fatal("native mapping/schema drift accepted")
			}
		})
	}
}
