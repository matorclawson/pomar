package prequal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Registry must be the maintained owning registrar, not a caller's Boolean or
// guest document. ClaimFreshRegistration verifies the original absent-name registration and atomically claims it for
// this phase, refusing a different original, a pre-existing-before-registration seat,
// prior session/mail and non-disposable row. An uncertain effect is held under
// the ORIGINAL operation. Retire must bind the actual instance/store/registered_at and captured
// command terminal plus independent readback, including split outcomes.
type Registry interface {
	ClaimFreshRegistration(context.Context, Plan) (Registration, error)
	Retire(context.Context, Registration) (Retirement, error)
}

// Command is issued by the owner phase only. No guest controls its executable,
// argv or UID. VM adapters may not hide bootstrap execs or start an agent.
type Command struct {
	Kind    string   `json:"kind"`
	Program string   `json:"program"`
	Args    []string `json:"args"`
	UID     int      `json:"uid"`
}
type Output struct {
	Exit  int    `json:"exit"`
	Bytes []byte `json:"bytes"`
}
type Drain struct {
	ScopeID       string `json:"scope_id"`
	LeaderReaped  bool   `json:"leader_reaped"`
	Stopped       bool   `json:"stopped"`
	LiveProcesses []int  `json:"live_processes"`
}

// VM is a distinct disposable owner backend, never the ordinary agent launch
// path. Boot stages the EXACT verified bytes and creates the VM but issues no
// hidden guest exec. Every guest exec is routed through Exec below. HostListing
// is the owning host's actual scope listing at drain, not a guest attestation.
// No concrete production adapter is supplied by this package.
type VM interface {
	Boot(context.Context, Plan, Registration) (scopeID string, err error)
	Exec(context.Context, Command) (Output, error)
	Stop(context.Context, string) (Drain, error)
	HostListing(context.Context, string) ([]byte, error)
}
type Result struct {
	ProbeObservation     json.RawMessage `json:"probe_observation,omitempty"`
	MailObservation      json.RawMessage `json:"mail_observation,omitempty"`
	Schema               string          `json:"schema"`
	State                string          `json:"state"`
	Plan                 Plan            `json:"plan"`
	Registration         *Registration   `json:"registration,omitempty"`
	Retirement           *Retirement     `json:"retirement,omitempty"`
	Executions           []Command       `json:"executions"`
	Drain                *Drain          `json:"drain,omitempty"`
	HostProcessListing   []byte          `json:"host_process_listing,omitempty"`
	TerminalPath         string          `json:"host_written_terminal_path"`
	AdmissionGranted     bool            `json:"admission_granted"`
	InteractiveQualified bool            `json:"interactive_qualified"`
}

func eventName(n int) string { return fmt.Sprintf("event-%06d.json", n) }
func verifyArtifact(a Artifact) error {
	f, e := os.OpenFile(a.Path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return errors.New("qualification artifact unavailable")
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > 1<<30 {
		return errors.New("qualification artifact not bounded regular")
	}
	// Lstat refuses a last-component symlink; canonical parent binding is also
	// required. The backend must stage these bytes, rechecking their pins.
	lst, e := os.Lstat(a.Path)
	if e != nil || !os.SameFile(st, lst) || lst.Mode()&os.ModeSymlink != 0 {
		return errors.New("qualification artifact custody changed")
	}
	real, e := filepath.EvalSymlinks(a.Path)
	if e != nil || real != a.Path {
		return errors.New("qualification artifact path not canonical")
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, (1<<30)+1))
	if e != nil || n > 1<<30 || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		return errors.New("qualification artifact pin changed")
	}
	return nil
}
func (j *journal) execute(ctx context.Context, v VM, c Command, r *Result) (Output, error) {
	// A closed executable set makes accidental broker/supervisor calls fail
	// before the backend sees them. Plan/guest JSON cannot expand it.
	if !(c.Kind == "isolation" && c.Program == "/pomar/isolation-probe" && c.UID == 1000 || c.Kind == "mail-d1" && c.Program == "/pomar/d1-driver" && c.UID == 1000 || c.Kind == "guest-process-list" && c.Program == "/bin/ps" && c.UID == 0) {
		return Output{}, errors.New("pre-model phase refuses broker, supervisor or arbitrary exec")
	}
	if e := j.event(struct {
		Stage   string
		Command Command
	}{"exec-before", c}); e != nil {
		return Output{}, e
	}
	r.Executions = append(r.Executions, c)
	out, e := v.Exec(ctx, c)
	if len(out.Bytes) > 1<<20 {
		return Output{}, errors.New("bounded exec output exceeded")
	}
	if je := j.event(struct {
		Stage   string
		Command Command
		Output  Output
		Failed  bool
	}{"exec-after", c, out, e != nil}); je != nil {
		return Output{}, je
	}
	if e != nil {
		return out, e
	}
	if out.Exit != 0 {
		return out, errors.New("qualification exec failed")
	}
	return out, nil
}
func noAgent(list []byte) bool {
	if len(strings.TrimSpace(string(list))) == 0 {
		return false
	}
	for _, line := range strings.Split(string(list), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 3 {
			return false
		}
		pid, pe := strconv.Atoi(f[0])
		uid, ue := strconv.Atoi(f[1])
		if pe != nil || ue != nil || pid < 1 || uid < 0 {
			return false
		}
		// ps format is pid, uid, comm; arguments cannot disguise an executable.
		switch filepath.Base(f[2]) {
		case "pomar-agent-guest", "agent-guest", "agent-broker", "seat-supervisor", "codex", "claude":
			return false
		}
	}
	return true
}

// Run creates an exclusive host journal before contacting any adapter. An
// existing/uncertain original is inspect-only. No result schema is accepted by
// ordinary seat profile/up, and even success leaves both authority flags false.
func Run(ctx context.Context, parent string, p Plan, reg Registry, v VM) (Result, error) {
	return run(ctx, parent, p, reg, v, verifyArtifact)
}
func run(ctx context.Context, parent string, p Plan, reg Registry, v VM, verify func(Artifact) error) (r Result, err error) {
	r = Result{Schema: ResultSchema, State: "unknown_retained", Plan: p, Executions: []Command{}}
	if ctx.Err() != nil {
		return r, ctx.Err()
	}
	if err = p.Validate(time.Now()); err != nil {
		return r, err
	}
	if reg == nil || v == nil {
		return r, errors.New("actual owning registry and disposable VM adapters required")
	}
	for _, a := range []Artifact{p.AgentArchive, p.Probe, p.ProbePlan, p.Driver} {
		if err = verify(a); err != nil {
			return r, err
		}
	}
	if ctx.Err() != nil || !p.Deadline.After(time.Now()) {
		return r, errors.New("original phase expired before allocation")
	}
	j, e := openJournal(parent, p.Operation)
	if e != nil {
		return r, e
	}
	r.TerminalPath = filepath.Join(j.dir, "terminal.json")
	if err = j.write("plan.json", p); err != nil {
		return r, err
	}
	phase, cancel := context.WithDeadline(ctx, p.Deadline)
	defer cancel()
	var row Registration
	registered, registrationAttempted, bootAttempted, complete := false, false, false, false
	scope := ""
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		safe := !bootAttempted
		if bootAttempted {
			// Collect process observations on failure too, then obtain a positive
			// owner stop/reap and host scope listing. Uncertainty keeps row/custody.
			if out, x := j.execute(cleanup, v, Command{"guest-process-list", "/bin/ps", []string{"-eo", "pid=,uid=,comm="}, 0}, &r); x != nil || !noAgent(out.Bytes) {
				err = errors.Join(err, errors.New("drain guest process observation failed"), x)
			}
			dr, x := v.Stop(cleanup, scope)
			r.Drain = &dr
			if x != nil {
				err = errors.Join(err, x)
			}
			safe = x == nil && scope != "" && dr.ScopeID == scope && dr.Stopped && dr.LeaderReaped && dr.LiveProcesses != nil && len(dr.LiveProcesses) == 0
			b, x := v.HostListing(cleanup, scope)
			if x != nil || len(b) == 0 || len(b) > 1<<20 {
				err = errors.Join(err, errors.New("actual bounded host process listing required"))
				safe = false
			} else {
				r.HostProcessListing = b
			}
		}
		if registered && safe {
			if x := j.event(struct {
				Stage string
				Row   Registration
			}{"retire-before", row}); x != nil {
				err = errors.Join(err, x)
				safe = false
			}
		}
		if registered && safe {
			rr, x := reg.Retire(cleanup, row)
			r.Retirement = &rr
			if x != nil || rr.Instance != row.Instance || rr.Store != row.Store || rr.RegisteredAt != row.RegisteredAt || rr.Operation != p.Operation || rr.Status != "retired" || rr.TerminalExit != 0 || rr.Teardown != "confirmed" || !sha.MatchString(rr.CommandTerminalSHA256) || !sha.MatchString(rr.ReadbackSHA256) {
				err = errors.Join(err, errors.New("original registration retirement unconfirmed"))
				safe = false
			} else {
				r.Retirement = &rr
			}
		}
		if complete && safe && err == nil {
			r.State = "observations_complete_requires_owner_join"
		} else if safe && err != nil && (!registrationAttempted || r.Retirement != nil) && !errors.Is(err, ErrEvidenceCustody) {
			r.State = "failed_stopped"
		} else {
			r.State = "unknown_retained"
		}
		if x := j.write("terminal.json", r); x != nil {
			r.State = "unknown_retained"
			err = errors.Join(err, x)
		}
		if r.State != "observations_complete_requires_owner_join" && err == nil {
			err = errors.New("qualification incomplete; inspect original retained custody")
		}
	}()
	if err = j.event(struct{ Stage string }{"claim-registration-before"}); err != nil {
		return r, err
	}
	if phase.Err() != nil {
		return r, phase.Err()
	}
	registrationAttempted = true
	row, err = reg.ClaimFreshRegistration(phase, p)
	if err != nil {
		return r, err
	}
	// Invalid returned rows are retained for reconciliation, not used or retired.
	r.Registration = &row
	if err = row.validate(p); err != nil {
		return r, err
	}
	registered = true
	if err = j.event(struct {
		Stage string
		Row   Registration
	}{"registered", row}); err != nil {
		return r, err
	}
	if phase.Err() != nil {
		return r, phase.Err()
	}
	if err = j.event(struct{ Stage string }{"boot-before"}); err != nil {
		return r, err
	}
	bootAttempted = true
	scope, err = v.Boot(phase, p, row)
	if err != nil {
		return r, err
	}
	if scope == "" {
		return r, errors.New("boot returned no actual owner scope")
	}
	// The probe's own deadline is at most60s within the original phase budget.
	probeEnd := time.Now().Add(55 * time.Second)
	if p.Deadline.Before(probeEnd) {
		probeEnd = p.Deadline
	}
	probe, pe := j.execute(phase, v, Command{"isolation", "/pomar/isolation-probe", []string{"-plan", "/pomar/probe-plan.json", "-plan-sha256", p.ProbePlan.SHA256, "-deadline", probeEnd.UTC().Format(time.RFC3339)}, 1000}, &r)
	if pe != nil {
		return r, pe
	}
	if err = probeObservation(probe.Bytes, p); err != nil {
		return r, err
	}
	r.ProbeObservation = append([]byte(nil), probe.Bytes...)
	mail, me := j.execute(phase, v, Command{"mail-d1", "/pomar/d1-driver", []string{"-seat", p.Seat, "-operation", p.Operation, "-deadline", p.Deadline.UTC().Format(time.RFC3339)}, 1000}, &r)
	if me != nil {
		return r, me
	}
	if !json.Valid(mail.Bytes) {
		return r, errors.New("actual structured D1 observations missing")
	}
	r.MailObservation = append([]byte(nil), mail.Bytes...)
	out, e := j.execute(phase, v, Command{"guest-process-list", "/bin/ps", []string{"-eo", "pid=,uid=,comm="}, 0}, &r)
	if e != nil {
		return r, e
	}
	if !noAgent(out.Bytes) {
		return r, errors.New("process listing missing or contains an agent/broker/supervisor")
	}
	for _, a := range []Artifact{p.AgentArchive, p.Probe, p.ProbePlan, p.Driver} {
		if err = verify(a); err != nil {
			return r, err
		}
	}
	if phase.Err() != nil {
		return r, phase.Err()
	}
	complete = true
	return r, nil
}
