package releaseexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"time"
)

type Kind string

const (
	PlanKind Kind = "plan"
	TagKind Kind = "tag"
	BuildKind Kind = "build"
	SignKind Kind = "sign"
	EventKind Kind = "event"
	SealKind Kind = "seal"
	PublishKind Kind = "publish"
	ConsumerKind Kind = "consumer"
)

var stages = [...]Kind{PlanKind, TagKind, BuildKind, SignKind, EventKind, SealKind, PublishKind, ConsumerKind}

// Observation is accepted only through Authority, never a caller branch label.
// Proof is public provenance evidence, not a credential or a fencing token.
type Observation struct {
	ID string
	Repository string
	Commit string
	Tree string
	Proof []byte
}

type Plan struct {
	Version string
	Tag string
	Notes []byte
	NotesSHA256 string
}

type Effect struct {
	ID string
	Kind Kind
	Observation Observation
	ConfigSHA256 string
	Prior []Receipt
}

type Receipt struct {
	ID string
	Kind Kind
	Outcome string
	EvidenceSHA256 string
	Plan Plan
	ArtifactSHA256 string
	InventorySHA256 string
	VerificationSHA256 string
	SharedEvent []byte
	SharedEventSHA256 string
	PayloadSHA256 string
	SignatureSHA256 string
}

type Record struct {
	Key string
	Observation Observation
	ConfigSHA256 string
	Revision uint64
	Next int
	InFlight bool
	Held bool
	Done bool
	Receipts []Receipt
}

// Journal must durably reserve the original before effects, serialize events per
// repository, and suspend its queue while an original is held. CAS is local
// release-intent concurrency control, NOT Runtime's accepted-job-result store.
// A failed/uncertain write must not be reported as durable success.
type Journal interface {
	Reserve(context.Context, Record) (Record, error)
	CompareAndSwap(context.Context, uint64, Record) error
}

// Authority is an owner-installed verifier. Actual main-movement/ancestry,
// section 6.2, profile/claim authority and accepted-result fencing live here.
// No bool, receipt hash or same-user label supplied by the event grants them.
type Authority interface {
	CheckConfig(context.Context, Config, string) error
	CheckObservation(context.Context, Observation) error
	CheckEffect(context.Context, Config, Effect) error
	CheckReceipt(context.Context, Config, Effect, Receipt) error
	CheckRecovery(context.Context, Config, Record) error
}

// Executor implements fixed owner profiles using the unchanged component and
// existing Pomar/signing providers. No executable, shell or version is supplied
// by the observation. Reconcile never starts or retries the work.
type Executor interface {
	Execute(context.Context, Effect) (Receipt, error)
	Reconcile(context.Context, Effect) (Receipt, error)
}

type Adapter struct {
	config Config
	configSHA256 string
	journal Journal
	authority Authority
	executor Executor
	now func() time.Time
}

func New(data []byte, pin string, j Journal, a Authority, e Executor, now func() time.Time) (*Adapter, error) {
	if missing(j) || missing(a) || missing(e) || now == nil {
		return nil, ErrUnbound
	}
	c, err := ParseConfig(data, pin)
	if err != nil {
		return nil, err
	}
	return &Adapter{c, pin, j, a, e, now}, nil
}

func missing(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		return r.IsNil()
	}
	return false
}

func copyObservation(o Observation) Observation {
	o.Proof = append([]byte(nil), o.Proof...)
	return o
}

func copyReceipts(in []Receipt) []Receipt {
	out := append([]Receipt(nil), in...)
	for i := range out {
		out[i].Plan.Notes = append([]byte(nil), out[i].Plan.Notes...)
		out[i].SharedEvent = append([]byte(nil), out[i].SharedEvent...)
	}
	return out
}

func (a *Adapter) original(ctx context.Context, o Observation) (Record, error) {
	o = copyObservation(o)
	if o.ID == "" || len(o.ID) > 256 || o.Repository != a.config.Repository ||
		!hexID(o.Commit, 40) || !hexID(o.Tree, 40) || len(o.Proof) == 0 || len(o.Proof) > MaxConfigBytes ||
		a.now().IsZero() || a.now().Unix() >= a.config.ValidUntil {
		return Record{}, ErrInvalid
	}
	if a.authority.CheckConfig(ctx, a.config, a.configSHA256) != nil || a.authority.CheckObservation(ctx, o) != nil {
		return Record{}, ErrHeld
	}
	key := hashBytes([]byte(o.Repository + "\x00" + o.ID))
	seed := Record{Key: key, Observation: o, ConfigSHA256: a.configSHA256, Receipts: []Receipt{}}
	r, err := a.journal.Reserve(ctx, seed)
	if err != nil {
		return Record{}, ErrDurability
	}
	if r.Key != key || r.ConfigSHA256 != a.configSHA256 || r.Observation.ID != o.ID ||
		r.Observation.Repository != o.Repository || r.Observation.Commit != o.Commit || r.Observation.Tree != o.Tree ||
		!bytes.Equal(r.Observation.Proof, o.Proof) {
		return Record{}, ErrConflict
	}
	if r.Next < 0 || r.Next > len(stages) || len(r.Receipts) != r.Next ||
		r.Done != (r.Next == len(stages)) || (r.Done && (r.InFlight || r.Held)) {
		return Record{}, ErrHeld
	}
	for i, receipt := range r.Receipts {
		effect := a.effect(r, i)
		if a.validateReceipt(effect, receipt) != nil || a.authority.CheckReceipt(ctx, a.config, effect, receipt) != nil {
			return Record{}, ErrHeld
		}
	}
	return r, nil
}

func (a *Adapter) effect(r Record, n int) Effect {
	kind := stages[n]
	return Effect{hashBytes([]byte(r.Key + "\x00" + string(kind))), kind,
		copyObservation(r.Observation), r.ConfigSHA256, copyReceipts(r.Receipts[:n])}
}

func (a *Adapter) save(ctx context.Context, r Record) error {
	old := r.Revision
	r.Revision++
	if a.journal.CompareAndSwap(ctx, old, r) != nil {
		return ErrDurability
	}
	return nil
}

// Step advances at most one effect. An interrupted persisted intent requires
// explicit Reconcile; duplicate delivery can never directly execute it again.
func (a *Adapter) Step(ctx context.Context, o Observation) (Record, error) {
	r, err := a.original(ctx, o)
	if err != nil || r.Done {
		return r, err
	}
	if r.Held || r.InFlight {
		return r, ErrHeld
	}
	effect := a.effect(r, r.Next)
	if a.authority.CheckEffect(ctx, a.config, effect) != nil {
		return r, ErrHeld
	}
	r.InFlight = true
	if err := a.save(ctx, r); err != nil {
		return r, err
	}
	r.Revision++
	if ctx.Err() != nil {
		return a.hold(ctx, r)
	}
	receipt, err := a.executor.Execute(ctx, effect)
	if err != nil || a.validateReceipt(effect, receipt) != nil ||
		a.authority.CheckReceipt(ctx, a.config, effect, receipt) != nil {
		return a.hold(ctx, r)
	}
	return a.finish(ctx, r, receipt)
}

func (a *Adapter) hold(ctx context.Context, r Record) (Record, error) {
	r.Held = true
	if err := a.save(ctx, r); err != nil {
		return Record{}, err
	}
	r.Revision++
	return r, ErrHeld
}

func (a *Adapter) finish(ctx context.Context, r Record, receipt Receipt) (Record, error) {
	r.Receipts = copyReceipts(append(copyReceipts(r.Receipts), receipt))
	r.Next++
	r.InFlight, r.Held = false, false
	r.Done = r.Next == len(stages)
	if err := a.save(ctx, r); err != nil {
		return Record{}, err
	}
	r.Revision++
	return r, nil
}

// Reconcile advances only a positively verified completed original. Unknown,
// failed and not-started outcomes stay held; no automatic replay or new ID.
// CheckRecovery must verify explicit owner recovery and renewed activation.
func (a *Adapter) Reconcile(ctx context.Context, o Observation) (Record, error) {
	r, err := a.original(ctx, o)
	if err != nil || r.Done {
		return r, err
	}
	if !r.InFlight || a.authority.CheckRecovery(ctx, a.config, r) != nil {
		return r, ErrHeld
	}
	effect := a.effect(r, r.Next)
	receipt, err := a.executor.Reconcile(ctx, effect)
	if err != nil || a.validateReceipt(effect, receipt) != nil ||
		a.authority.CheckReceipt(ctx, a.config, effect, receipt) != nil {
		return a.hold(ctx, r)
	}
	return a.finish(ctx, r, receipt)
}

func (a *Adapter) validateReceipt(e Effect, r Receipt) error {
	if r.ID != e.ID || r.Kind != e.Kind || r.Outcome != "completed" || !hexID(r.EvidenceSHA256, 64) {
		return ErrInvalid
	}
	switch e.Kind {
	case PlanKind:
		if r.Plan.Version == "" || len(r.Plan.Version) > 128 || len(r.Plan.Tag) > 256 ||
			len(r.Plan.Tag) <= len(a.config.TagPrefix) || r.Plan.Tag[:len(a.config.TagPrefix)] != a.config.TagPrefix ||
			len(r.Plan.Notes) > MaxConfigBytes || hashBytes(r.Plan.Notes) != r.Plan.NotesSHA256 {
			return ErrInvalid
		}
	case BuildKind:
		if !hexID(r.ArtifactSHA256, 64) {
			return ErrInvalid
		}
	case SignKind:
		if !hexID(r.ArtifactSHA256, 64) || !hexID(r.InventorySHA256, 64) || !hexID(r.VerificationSHA256, 64) {
			return ErrInvalid
		}
	case EventKind:
		if len(r.SharedEvent) == 0 || len(r.SharedEvent) > a.config.Limits.EnvelopeBytes ||
			!json.Valid(r.SharedEvent) || hashBytes(r.SharedEvent) != r.SharedEventSHA256 ||
			len(e.Prior) < 4 || r.ArtifactSHA256 != e.Prior[3].ArtifactSHA256 {
			return ErrInvalid
		}
	case SealKind:
		if !hexID(r.PayloadSHA256, 64) || !hexID(r.SignatureSHA256, 64) || !hexID(r.VerificationSHA256, 64) {
			return ErrInvalid
		}
	}
	return nil
}
