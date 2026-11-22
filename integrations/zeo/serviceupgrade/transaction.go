// Package serviceupgrade upgrades an existing service and supports an
// explicitly bound migration of its launchd and binary signing identities.
package serviceupgrade

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type Observation struct {
	Pin            string `json:"pin"`
	History        string `json:"history_sha256"`
	KeyID          string `json:"key_id"`
	PID            int    `json:"pid"`
	Birth          string `json:"process_birth"`
	Capacity       string `json:"capacity_binding_sha256"`
	CallerHistory  string `json:"caller_history_sha256"`
	OwnerCapacity  string `json:"owner_capacity_sha256"`
	CallerCapacity string `json:"caller_capacity_sha256"`
}

type Journal struct {
	Schema        string      `json:"schema"`
	ManifestSHA   string      `json:"manifest_sha256"`
	Phase         string      `json:"phase"`
	Before        Observation `json:"before"`
	Archive       string      `json:"archive"`
	SigningPolicy string      `json:"signing_policy"`
	FromStartup   bool        `json:"rollback_from_startup,omitempty"`
}

// Driver methods are narrow, checked operations, not caller-supplied commands.
// Check and Observe are read-only. Stop must recheck the named process identity.
// Replace and Restore refuse bytes outside the frozen baseline/target set.
type Driver interface {
	SigningPolicy() string
	Check(context.Context) error
	Observe(context.Context) (Observation, error)
	Archive(context.Context, Observation) (string, error)
	Save(Journal) error
	Fence(context.Context) error
	Stop(context.Context, Observation) error
	Replace(context.Context) error
	Start(context.Context) error
	Verify(context.Context, Observation) error
	Open(context.Context) error
	Restore(context.Context, Journal) error
}

// Inspect performs no lock creation, journal write or service mutation.
func Inspect(ctx context.Context, d Driver) (Observation, error) {
	if err := d.Check(ctx); err != nil {
		return Observation{}, err
	}
	return d.Observe(ctx)
}

func Apply(ctx context.Context, d Driver, manifestSHA string) (Journal, error) {
	return apply(ctx, d, manifestSHA, nil)
}

func apply(ctx context.Context, d Driver, manifestSHA string, recover func(context.Context, Journal) (Journal, error)) (Journal, error) {
	before, err := Inspect(ctx, d)
	if err != nil {
		return Journal{}, err
	}
	archive, err := d.Archive(ctx, before)
	if err != nil {
		return Journal{}, err
	}
	j := Journal{Schema: "pomar.service-upgrade-journal/v1", ManifestSHA: manifestSHA, Phase: "prepared", Before: before, Archive: archive, SigningPolicy: d.SigningPolicy()}
	stopping := false
	fail := func(cause error) (Journal, error) {
		failure := fmt.Errorf("upgrade incomplete at %s; retained archive %s: %w", j.Phase, j.Archive, cause)
		if recover == nil || !stopping {
			return j, fmt.Errorf("%w; admission must be reconciled", failure)
		}
		// Do not inherit cancellation from the failed forward operation.
		recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
		defer cancel()
		recovered, recoveryErr := recover(recoveryCtx, j)
		if recoveryErr != nil {
			return recovered, errors.Join(failure, fmt.Errorf("automatic recovery incomplete; reconcile the original archive: %w", recoveryErr))
		}
		return recovered, fmt.Errorf("%w; original service restored and verified", failure)
	}
	step := func(phase string, act func() error) error {
		// Retain intent before its effect: a crash cannot look like no change.
		j.Phase = phase
		stopping = stopping || phase == "stopping"
		if err := d.Save(j); err != nil {
			return err
		}
		return act()
	}
	operations := []struct {
		phase string
		act   func() error
	}{
		{"fencing", func() error { return d.Fence(ctx) }},
		{"stopping", func() error {
			now, err := d.Observe(ctx)
			if err != nil {
				return err
			}
			if now != before {
				return fmt.Errorf("service identity, history or key changed before stop")
			}
			return d.Stop(ctx, before)
		}},
		{"installing", func() error { return d.Replace(ctx) }},
		{"starting", func() error { return d.Start(ctx) }},
		{"verifying", func() error { return d.Verify(ctx, before) }},
		{"opening", func() error { return d.Open(ctx) }},
	}
	for _, op := range operations {
		if err = step(op.phase, op.act); err != nil {
			return fail(err)
		}
	}
	j.Phase = "complete"
	err = d.Save(j)
	if err != nil {
		if recover != nil {
			return fail(fmt.Errorf("admission reopened before completion journal failed: %w", err))
		}
		return j, fmt.Errorf("admission reopened but completion journal failed; inspect retained archive before recovery: %w", err)
	}
	return j, err
}

func Rollback(ctx context.Context, d Driver, j Journal, manifestSHA string) (Journal, error) {
	if j.Schema != "pomar.service-upgrade-journal/v1" || j.ManifestSHA != manifestSHA || j.Archive == "" || j.SigningPolicy != d.SigningPolicy() {
		return j, fmt.Errorf("rollback requires the original frozen manifest and archive")
	}
	if err := d.Check(ctx); err != nil {
		return j, err
	}
	j.FromStartup = j.Phase == "starting" || (j.Phase == "rolling-back" && j.FromStartup)
	j.Phase = "rolling-back"
	if err := d.Save(j); err != nil {
		return j, err
	}
	if err := d.Fence(ctx); err != nil {
		return j, err
	}
	// Restore must either stop a positively matched idle current manager or
	// prove the service and all its writers absent. It cannot replace live files.
	if err := d.Restore(ctx, j); err != nil {
		return j, err
	}
	if err := d.Start(ctx); err != nil {
		return j, err
	}
	if err := d.Verify(ctx, j.Before); err != nil {
		return j, err
	}
	if err := d.Open(ctx); err != nil {
		return j, err
	}
	j.Phase = "rolled-back"
	j.FromStartup = false
	if err := d.Save(j); err != nil {
		return j, fmt.Errorf("baseline admission reopened but rollback journal failed; inspect retained archive: %w", err)
	}
	return j, nil
}
