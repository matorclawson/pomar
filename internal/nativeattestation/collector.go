package nativeattestation

// sow: pomar-SOW-90
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/result"
)

var ErrUnavailable = errors.New("native attestation: protected observer unavailable")
var ErrHeld = errors.New("native attestation: original remains held")

// No observer can be registered through the public library surface. Connecting
// the real protected receiver requires separately scoped source and adoption.
// CheckOriginal authenticates the original journal, current caller and policy;
// Observe reads owner-held evidence, never starts/retries an execution; Freeze
// atomically binds exact bytes to that original and refuses conflicting replay.
type nativeObserver interface {
	CheckOriginal(context.Context, Original, string) error
	Observe(context.Context, Original) (observation, error)
	Freeze(context.Context, Original, []byte) ([]byte, error)
}

type observation struct {
	proof     Proof
	stdout    []byte
	stderr    []byte
	artifacts map[string][]byte
}

type Collector struct {
	policy   Policy
	observer nativeObserver
}

// NewCollector freezes owner policy but deliberately has no installed observer.
// A valid policy or a caller-constructed Proof cannot enable native collection.
func NewCollector(policy Policy) (*Collector, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	b, err := result.Canonical(policy)
	if err != nil {
		return nil, err
	}
	var frozen Policy
	if err = json.Unmarshal(b, &frozen); err != nil {
		return nil, err
	}
	return &Collector{policy: frozen}, nil
}

// Collected contains only exact journal-frozen bytes. Bytes returns a copy.
// Its zero value is not a proof. No Signer/key is created or stored here.
type Collected struct{ doc []byte }

func (c Collected) Bytes() []byte { return bytes.Clone(c.doc) }

func held(err error) error { return fmt.Errorf("%w: %w", ErrHeld, err) }

// Collect never admits/runs/retries work or refunds custody. Any unavailable,
// canceled, changed, partial or conflicting observation stays held on ORIGINAL.
func (c *Collector) Collect(ctx context.Context, original Original, now time.Time) (Collected, error) {
	if c == nil || c.observer == nil {
		return Collected{}, held(ErrUnavailable)
	}
	if ctx == nil {
		return Collected{}, held(ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return Collected{}, held(err)
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || deadline.After(original.Deadline) {
		return Collected{}, held(ErrInvalid)
	}
	policyID, err := c.policy.Digest()
	if err != nil {
		return Collected{}, held(err)
	}
	if err = c.policy.checkOriginal(original, now); err != nil {
		return Collected{}, held(err)
	}
	if err = c.observer.CheckOriginal(ctx, original, policyID); err != nil {
		return Collected{}, held(err)
	}
	if err = ctx.Err(); err != nil {
		return Collected{}, held(err)
	}
	observed, err := c.observer.Observe(ctx, original)
	if err != nil {
		return Collected{}, held(err)
	}
	if err = ctx.Err(); err != nil {
		return Collected{}, held(err)
	}
	if err = c.policy.Check(observed.proof, original, now); err != nil {
		return Collected{}, held(err)
	}
	// Hash exact bounded owner-held raw bytes; never open a caller-chosen path.
	if int64(len(observed.stdout)) != observed.proof.Stdout.Bytes || int64(len(observed.stderr)) != observed.proof.Stderr.Bytes || digest(observed.stdout) != observed.proof.Stdout.SHA256 || digest(observed.stderr) != observed.proof.Stderr.SHA256 || len(observed.artifacts) != len(observed.proof.Artifacts) {
		return Collected{}, held(ErrInvalid)
	}
	for _, artifact := range observed.proof.Artifacts {
		data, exists := observed.artifacts[artifact.Name]
		if !exists || int64(len(data)) != artifact.Bytes || digest(data) != artifact.SHA256 {
			return Collected{}, held(ErrInvalid)
		}
	}
	doc, err := Canonical(observed.proof)
	if err != nil {
		return Collected{}, held(err)
	}
	// Fresh owner check after hashing/copying prevents a revoked original from
	// being lent the earlier callback's authority. No release method exists.
	if err = c.observer.CheckOriginal(ctx, original, policyID); err != nil {
		return Collected{}, held(err)
	}
	if err = ctx.Err(); err != nil {
		return Collected{}, held(err)
	}
	retained, err := c.observer.Freeze(ctx, original, bytes.Clone(doc))
	if err != nil {
		return Collected{}, held(err)
	}
	if !bytes.Equal(retained, doc) {
		return Collected{}, held(ErrInvalid)
	}
	ready := bytes.Clone(retained)
	if err = c.observer.CheckOriginal(ctx, original, policyID); err != nil {
		return Collected{}, held(err)
	}
	if err = ctx.Err(); err != nil {
		return Collected{}, held(err)
	}
	return Collected{doc: ready}, nil
}
