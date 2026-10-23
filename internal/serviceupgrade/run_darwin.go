//go:build darwin

package serviceupgrade

import (
	"context"
	"fmt"
	"os"
	"strings"
)

func Execute(ctx context.Context, action, bundle, sha, archive string) (any, error) {
	if action == "stage" {
		path, err := Stage(ctx, bundle, sha)
		return map[string]string{"schema": "pomar.service-upgrade-stage/v1", "stage": path, "manifest_sha256": sha}, err
	}
	n, err := LoadNative(bundle, sha)
	if err != nil {
		return nil, err
	}
	defer n.Close()
	n.Progress = os.Stderr
	switch action {
	case "check":
		if archive != "" {
			j, err := n.LoadRollback(archive)
			if err != nil {
				return nil, err
			}
			if err = n.Check(ctx); err != nil {
				return nil, err
			}
			return n.recoveryObservation(ctx, j)
		}
		return Inspect(ctx, n)
	case "apply":
		if archive != "" {
			return nil, fmt.Errorf("apply creates a new archive; it cannot reuse an old operation")
		}
		if err = n.identity(ctx); err != nil {
			return nil, err
		}
		if err = n.Lock(); err != nil {
			return nil, err
		}
		return Apply(ctx, n, sha)
	case "resume-opening":
		if archive == "" {
			return nil, fmt.Errorf("resume-opening requires the original -archive")
		}
		if err = n.identity(ctx); err != nil {
			return nil, err
		}
		if err = n.Lock(); err != nil {
			return nil, err
		}
		j, err := n.LoadRollback(archive)
		if err != nil {
			return nil, err
		}
		if !openingPhase(j.Phase) {
			return j, fmt.Errorf("only an interrupted original opening may resume")
		}
		// LoadRollback checks both allowed byte sets and original identity.
		if err = n.Check(ctx); err != nil {
			return j, err
		}
		n.rollback = strings.HasPrefix(j.Phase, "rollback-opening")
		if err = n.Fence(ctx); err != nil {
			return j, err
		}
		if err = n.closeControl(); err != nil {
			return j, err
		}
		if err = n.Verify(ctx, j.Before); err != nil {
			return j, err
		}
		if err = n.Open(ctx); err != nil {
			return n.original, err
		}
		j = n.original
		j.Phase = "complete"
		if n.rollback {
			j.Phase = "rolled-back"
		}
		if err = n.Save(j); err != nil {
			return j, fmt.Errorf("admission opened; completion journal failed: %w", err)
		}
		return j, nil
	case "rollback":
		if archive == "" {
			return nil, fmt.Errorf("rollback requires the original -archive")
		}
		if err = n.identity(ctx); err != nil {
			return nil, err
		}
		if err = n.Lock(); err != nil {
			return nil, err
		}
		j, err := n.LoadRollback(archive)
		if err != nil {
			return nil, err
		}
		return Rollback(ctx, n, j, sha)
	default:
		return nil, fmt.Errorf("unknown upgrade operation")
	}
}
