package prequal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"time"
)

// Transport is the owner backend's observed start of the one maintained relay
// shim. Handle names its actual process in the original scope; it is not a PID
// inferred from a log. Stop must drain this handle along with the whole VM.
type Transport struct {
	ScopeID   string  `json:"scope_id"`
	Operation string  `json:"operation"`
	Handle    string  `json:"owner_process_handle"`
	Command   Command `json:"command"`
	Ready     bool    `json:"ready"`
}

func mailShimArgs() []string {
	return []string{"/pomar/shim", "-listen", "127.0.0.1:7743", "-socket", "/run/pomar/mail.sock", "-ready", "/pomar/shim-mail.ready"}
}
func shimCommand() Command { return Command{"mail-transport", "/pomar/shim", mailShimArgs()[1:], 0} }
func collectorCommand(scope string) Command {
	return Command{"owner-guest-inventory", "/pomar/d1-driver", []string{"-mode", "processes", "-scope", scope}, 0}
}
func mailArgs(p Plan) []string {
	return []string{"-mode", "mail", "-seat", p.Seat, "-operation", p.Operation, "-deadline", p.Deadline.UTC().Format(time.RFC3339)}
}
func allowedPhaseCommand(c Command, p Plan, scope string) bool {
	if scope == "" {
		return false
	}
	switch c.Kind {
	case "guest-process-list":
		return c.Program == "/bin/ps" && c.UID == 0 && slices.Equal(c.Args, []string{"-eo", "pid=,uid=,args="})
	case "owner-guest-inventory":
		return c.Program == "/pomar/d1-driver" && c.UID == 0 && slices.Equal(c.Args, collectorCommand(scope).Args)
	case "mail-d1":
		return c.Program == "/pomar/d1-driver" && c.UID == 1000 && slices.Equal(c.Args, mailArgs(p))
	case "isolation":
		if c.Program != "/pomar/isolation-probe" || c.UID != 1000 || len(c.Args) != 6 || !slices.Equal(c.Args[:5], []string{"-plan", "/pomar/probe-plan.json", "-plan-sha256", p.ProbePlan.SHA256, "-deadline"}) {
			return false
		}
		end, e := time.Parse(time.RFC3339, c.Args[5])
		return e == nil && end.After(time.Now()) && !end.After(p.Deadline) && !end.After(time.Now().Add(55*time.Second))
	}
	return false
}
func (j *journal) startTransport(ctx context.Context, v VM, r *Result) error {
	c := shimCommand()
	if r.ScopeID == "" {
		return errors.New("transport needs original owned scope")
	}
	if e := j.event(struct {
		Stage   string
		Command Command
	}{"transport-start-before", c}); e != nil {
		return e
	}
	sent := c
	sent.Args = append([]string(nil), c.Args...)
	t, e := v.StartTransport(ctx, r.ScopeID, r.Plan.Operation, sent)
	want := shimCommand()
	r.Transport = &t
	valid := t.ScopeID == r.ScopeID && t.Operation == r.Plan.Operation && len(t.Handle) > 0 && len(t.Handle) <= 256 && t.Ready && t.Command.Kind == want.Kind && t.Command.Program == want.Program && t.Command.UID == want.UID && slices.Equal(t.Command.Args, want.Args)
	if je := j.event(struct {
		Stage     string
		Transport Transport
		Failed    bool
	}{"transport-start-after", t, e != nil || !valid}); je != nil {
		return je
	}
	if e != nil {
		return e
	}
	if !valid {
		return errors.New("original transport start or readiness unconfirmed")
	}
	return nil
}
func parseInventory(raw []byte, scope string) (ProcessSnapshot, error) {
	var s ProcessSnapshot
	if len(raw) == 0 || len(raw) > 1<<20 {
		return s, errors.New("bounded owner-executed guest inventory required")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if e := dec.Decode(&s); e != nil {
		return s, e
	}
	var trailing any
	if dec.Decode(&trailing) != io.EOF {
		return s, errors.New("trailing inventory document")
	}
	if e := validateProcesses(s, scope); e != nil {
		return s, e
	}
	shim, collector := 0, 0
	for _, row := range s.Rows {
		if row.Exe == "/pomar/shim" {
			shim++
		}
		if row.Exe == "/pomar/d1-driver" && row.UID == 0 {
			collector++
		}
	}
	if shim != 1 || collector != 1 {
		return s, errors.New("one live exact relay shim and root collector required")
	}
	return s, nil
}
