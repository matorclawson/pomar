// Package webservice models a fixed-port service cutover. It has no host,
// process, routing, database, or privilege adapter. Evidence digests refer to
// observations a future trusted adapter must verify; they are not proof by
// themselves. No function here starts or stops an application.
package webservice

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

var (
	ErrConflict = errors.New("webservice conflict")
	ErrHeld     = errors.New("webservice operation held")
	ErrCapacity = errors.New("webservice receipt capacity reached")
	idPattern   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}$`)
)

// Receipt capacity is deliberately finite. Admission refuses when full; it must
// never evict an original operation to make space or silently permit ID reuse.
// Production archival/index design remains outside this model.
const MaxOperations = 256

const maxHistory = 16

// Request binds admitted inputs by digest, without accepting executable paths,
// arbitrary commands, credentials, or unit names. Policy admission and native
// verification are outside this source model.
type Request struct {
	ID               string `json:"id"`
	Epoch            uint64 `json:"epoch"`
	ExpectedPrevious string `json:"expected_previous"`
	Release          string `json:"release"`
	Profile          string `json:"profile"`
	Database         string `json:"database"`
}

func digest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (r Request) validate() error {
	if !idPattern.MatchString(r.ID) || r.Epoch == 0 {
		return errors.New("invalid operation identity")
	}
	for _, d := range []string{r.ExpectedPrevious, r.Release, r.Profile, r.Database} {
		if !digest(d) {
			return errors.New("invalid input digest")
		}
	}
	if r.Release == r.ExpectedPrevious {
		return errors.New("candidate equals previous release")
	}
	return nil
}

func (r Request) hash() string {
	b, _ := json.Marshal(r) // fixed fields only; encoding cannot fail
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

type Phase string

const (
	Prepared                  Phase = "prepared"
	MaintenanceIntent         Phase = "maintenance_intent"
	StopIntent                Phase = "stop_previous_intent"
	PreviousGone              Phase = "previous_departure_observed"
	APIStartIntent            Phase = "start_api_intent"
	WebStartIntent            Phase = "start_web_intent"
	ReopenIntent              Phase = "reopen_route_intent"
	Complete                  Phase = "complete"
	Held                      Phase = "held_unknown"
	RollbackMaintenanceIntent Phase = "rollback_maintenance_intent"
	CandidateStopIntent       Phase = "stop_candidate_intent"
	PreviousAPIStartIntent    Phase = "restart_previous_api_intent"
	PreviousWebStartIntent    Phase = "restart_previous_web_intent"
	RollbackReopenIntent      Phase = "rollback_reopen_route_intent"
	RolledBack                Phase = "rolled_back"
)

type EventKind string

const (
	RequestMaintenance        EventKind = "request_maintenance"
	MaintenanceClosed         EventKind = "maintenance_closed"
	PreviousDeparted          EventKind = "previous_departed"
	RequestAPI                EventKind = "request_api"
	APIHealthy                EventKind = "api_healthy"
	WebHealthy                EventKind = "web_healthy"
	RouteHealthy              EventKind = "route_healthy"
	OutcomeUnknown            EventKind = "outcome_unknown"
	CandidateFailed           EventKind = "candidate_failed"
	RollbackMaintenanceClosed EventKind = "rollback_maintenance_closed"
	CandidateDeparted         EventKind = "candidate_departed"
	PreviousAPIHealthy        EventKind = "previous_api_healthy"
	PreviousWebHealthy        EventKind = "previous_web_healthy"
	PreviousRouteHealthy      EventKind = "previous_route_healthy"
)

// Event must name the retained operation, epoch, and expected phase. Revision
// CAS prevents stale/concurrent observations from changing the current record.
// Observations must reference exact independently verified evidence; this model
// validates only the reference shape, not the evidence's native semantics.
type Event struct {
	ID       string
	Epoch    uint64
	From     Phase
	Kind     EventKind
	Evidence string
}

type Operation struct {
	Request Request
	Hash    string
	Phase   Phase
	History []Event
}

// State is one atomic custody record. A nonempty Active holds the fence even
// after an unknown outcome. Database is the admitted persistent database identity
// and never changes during cutover. Ordinary code cutover never restores it.
// The administrator-provisioned Store custody owner establishes Epoch before
// first admission. It may advance it only at a reviewed, idle custody handoff
// with no Active operation and complete native departure reconciliation. The
// Engine never advances it per transition. Changing it under an active fence
// invalidates that state; it is not a way to clear unknown custody. A production
// owner/handoff adapter is not supplied here.
type State struct {
	Revision   uint64
	Epoch      uint64
	Current    string
	Database   string
	Active     string
	Operations map[string]Operation
}

// Store implementations must return detached snapshots. CompareAndSwap must
// atomically and durably publish the entire next state or leave the prior state
// intact, and return ErrConflict on a revision mismatch. An ambiguous commit is
// an error: inspect the same operation before retrying. This package supplies no
// production store, lock namespace, or host adapter.
// Load must bound input bytes before decoding; the model additionally refuses
// oversized operation/history collections before iterating them.
type Store interface {
	Load() (State, error)
	CompareAndSwap(revision uint64, next State) error
}

type Engine struct{ Store Store }

func validateState(s State) error {
	if s.Epoch == 0 || s.Revision == ^uint64(0) || !digest(s.Current) || !digest(s.Database) {
		return errors.New("invalid retained custody state")
	}
	if len(s.Operations) > MaxOperations {
		return ErrCapacity
	}
	for id, op := range s.Operations {
		if id != op.Request.ID || op.Request.validate() != nil || op.Hash != op.Request.hash() {
			return errors.New("invalid retained operation binding")
		}
		if len(op.History) > maxHistory {
			return errors.New("retained history exceeds model capacity")
		}
		phase := Prepared
		for _, v := range op.History {
			next, ok := transition(phase, v.Kind)
			if !ok || v.ID != id || v.Epoch != op.Request.Epoch || v.From != phase || !validEvidence(v) {
				return errors.New("invalid retained transition history")
			}
			phase = next
		}
		if op.Phase != phase || (!terminal(phase) && id != s.Active) {
			return errors.New("invalid retained phase or fence")
		}
	}
	if s.Active != "" {
		op, ok := s.Operations[s.Active]
		if !ok || terminal(op.Phase) || op.Request.Epoch != s.Epoch || op.Request.ExpectedPrevious != s.Current || op.Request.Database != s.Database {
			return errors.New("invalid active fence")
		}
	}
	return nil
}

func validEvidence(v Event) bool {
	if v.Kind == RequestMaintenance || v.Kind == RequestAPI {
		return v.Evidence == ""
	}
	return digest(v.Evidence)
}

// Begin records intent before any future adapter effect. Identical retries read
// the original operation even after current changes; changed inputs conflict.
func (e Engine) Begin(r Request) (Operation, error) {
	if err := r.validate(); err != nil {
		return Operation{}, err
	}
	s, err := e.Store.Load()
	if err != nil {
		return Operation{}, err
	}
	if err := validateState(s); err != nil {
		return Operation{}, err
	}
	if old, ok := s.Operations[r.ID]; ok {
		if old.Hash != r.hash() {
			return Operation{}, ErrConflict
		}
		return old, nil
	}
	if s.Active != "" {
		return Operation{}, ErrHeld
	}
	if r.Epoch != s.Epoch || r.ExpectedPrevious != s.Current || r.Database != s.Database {
		return Operation{}, ErrConflict
	}
	if len(s.Operations) >= MaxOperations {
		return Operation{}, ErrCapacity
	}
	op := Operation{Request: r, Hash: r.hash(), Phase: Prepared}
	if s.Operations == nil {
		s.Operations = make(map[string]Operation)
	}
	s.Operations[r.ID], s.Active = op, r.ID
	rev := s.Revision
	s.Revision++
	if err := e.Store.CompareAndSwap(rev, s); err != nil {
		return Operation{}, err
	}
	return op, nil
}

func transition(p Phase, k EventKind) (Phase, bool) {
	if k == OutcomeUnknown && !terminal(p) && p != Held {
		return Held, true
	}
	switch {
	case p == Prepared && k == RequestMaintenance:
		return MaintenanceIntent, true
	case p == MaintenanceIntent && k == MaintenanceClosed:
		return StopIntent, true
	case p == StopIntent && k == PreviousDeparted:
		return PreviousGone, true
	case p == PreviousGone && k == RequestAPI:
		return APIStartIntent, true
	case p == APIStartIntent && k == APIHealthy:
		return WebStartIntent, true
	case p == WebStartIntent && k == WebHealthy:
		return ReopenIntent, true
	case p == ReopenIntent && k == RouteHealthy:
		return Complete, true
	case (p == APIStartIntent || p == WebStartIntent || p == ReopenIntent) && k == CandidateFailed:
		return RollbackMaintenanceIntent, true
	case p == RollbackMaintenanceIntent && k == RollbackMaintenanceClosed:
		return CandidateStopIntent, true
	case p == CandidateStopIntent && k == CandidateDeparted:
		return PreviousAPIStartIntent, true
	case p == PreviousAPIStartIntent && k == PreviousAPIHealthy:
		return PreviousWebStartIntent, true
	case p == PreviousWebStartIntent && k == PreviousWebHealthy:
		return RollbackReopenIntent, true
	case p == RollbackReopenIntent && k == PreviousRouteHealthy:
		return RolledBack, true
	}
	return "", false
}

func terminal(p Phase) bool { return p == Complete || p == RolledBack }

// Advance persists a model transition. It performs no native effect. Held
// outcomes deliberately have no generic clear/retry path: native reconciliation
// and control authority have not been defined or implemented in this slice.
func (e Engine) Advance(v Event) (Operation, error) {
	s, err := e.Store.Load()
	if err != nil {
		return Operation{}, err
	}
	if err := validateState(s); err != nil {
		return Operation{}, err
	}
	op, ok := s.Operations[v.ID]
	if !ok || s.Active != v.ID || v.Epoch != s.Epoch || op.Request.Epoch != s.Epoch || v.From != op.Phase {
		return Operation{}, ErrConflict
	}
	if op.Phase == Held {
		return Operation{}, ErrHeld
	}
	next, ok := transition(op.Phase, v.Kind)
	if !ok {
		return Operation{}, fmt.Errorf("refused transition %s/%s", op.Phase, v.Kind)
	}
	if !validEvidence(v) {
		return Operation{}, errors.New("missing observation evidence reference")
	}
	op.Phase = next
	op.History = append(op.History, v)
	s.Operations[v.ID] = op
	if next == Complete {
		s.Current, s.Active = op.Request.Release, ""
	} else if next == RolledBack {
		// Previous remains Current, and the same Database identity is retained.
		s.Active = ""
	}
	rev := s.Revision
	s.Revision++
	if err := e.Store.CompareAndSwap(rev, s); err != nil {
		return Operation{}, err
	}
	return op, nil
}
