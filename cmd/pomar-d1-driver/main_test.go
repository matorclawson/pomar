package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/prequal"
)

var exactArgs = []string{"-mode", "processes", "-scope", "original"}

func observation(scope string) prequal.ProcessSnapshot {
	return prequal.ProcessSnapshot{ScopeID: scope, Kind: prequal.OwnerGuestInventoryKind, Rows: []prequal.ProcessRow{{PID: 7, UID: 1000, Exe: "/unexpected/program", Args: []string{"/unexpected/program", "not filtered"}}}}
}

func TestClosedArgsRefuseWithoutCallingObserver(t *testing.T) {
	for _, args := range [][]string{nil, {"-mode", "mail"}, {"-scope", "original", "-mode", "processes"}, {"-mode", "processes", "-scope", ""}, {"-mode", "processes", "-scope", strings.Repeat("x", 257)}, {"-mode", "processes", "-scope", "original", "/proc/other"}} {
		var out, err bytes.Buffer
		rc := run(context.Background(), args, &out, &err, func(context.Context, string) (prequal.ProcessSnapshot, error) {
			t.Fatal("invalid args reached observer")
			return prequal.ProcessSnapshot{}, nil
		})
		if rc != 2 || out.Len() != 0 || err.Len() == 0 {
			t.Fatalf("bad refusal: %d %s %s", rc, &out, &err)
		}
	}
}

func TestObservationRetainsUnexpectedProcessesAndBindsScope(t *testing.T) {
	var out, diagnostic bytes.Buffer
	rc := run(context.Background(), exactArgs, &out, &diagnostic, func(ctx context.Context, scope string) (prequal.ProcessSnapshot, error) {
		end, ok := ctx.Deadline()
		if !ok || time.Until(end) > 20*time.Second || scope != "original" {
			t.Fatal("missing bounded original context")
		}
		return observation(scope), nil
	})
	var got prequal.ProcessSnapshot
	if rc != 0 || diagnostic.Len() != 0 || json.Unmarshal(out.Bytes(), &got) != nil || len(got.Rows) != 1 || got.Rows[0].Exe != "/unexpected/program" || got.ScopeID != "original" || got.Kind != prequal.OwnerGuestInventoryKind {
		t.Fatalf("observation filtered, rebound or invalid: %d %s %s", rc, &out, &diagnostic)
	}
}

func TestFailureCancellationAndOversizeHaveNoPositivePayload(t *testing.T) {
	for _, kind := range []string{"error", "wrong-scope", "wrong-kind", "empty", "oversize", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var out, diagnostic bytes.Buffer
			rc := run(ctx, exactArgs, &out, &diagnostic, func(context.Context, string) (prequal.ProcessSnapshot, error) {
				s := observation("original")
				switch kind {
				case "error":
					return s, errors.New("observer refused")
				case "wrong-scope":
					s.ScopeID = "other"
				case "wrong-kind":
					s.Kind = prequal.HostAfterStopKind
				case "empty":
					s.Rows = nil
				case "oversize":
					s.Rows[0].Args = []string{strings.Repeat("x", observationLimit)}
				case "cancel":
					cancel()
				}
				return s, nil
			})
			if rc != 1 || out.Len() != 0 || diagnostic.Len() == 0 {
				t.Fatalf("positive payload after %s: %d %s", kind, rc, &out)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, diagnostic bytes.Buffer
	if run(ctx, exactArgs, &out, &diagnostic, func(context.Context, string) (prequal.ProcessSnapshot, error) {
		t.Fatal("canceled call reached observer")
		return prequal.ProcessSnapshot{}, nil
	}) != 1 {
		t.Fatal("canceled original accepted")
	}
}

type shortWriter struct{}

func (shortWriter) Write([]byte) (int, error) { return 0, nil }

func TestOutputFailureIsNotSuccess(t *testing.T) {
	var diagnostic bytes.Buffer
	if run(context.Background(), exactArgs, shortWriter{}, &diagnostic, func(context.Context, string) (prequal.ProcessSnapshot, error) { return observation("original"), nil }) != 1 || diagnostic.Len() == 0 {
		t.Fatal("short output accepted")
	}
}

func TestActualNonLinuxReaderRefusesWithoutPayload(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("actual Linux namespace requires owner qualification")
	}
	var out, diagnostic bytes.Buffer
	if run(context.Background(), exactArgs, &out, &diagnostic, prequal.CollectLinuxProcessSnapshot) != 1 || out.Len() != 0 || !strings.Contains(diagnostic.String(), "requires Linux root") {
		t.Fatal("non-Linux reader produced an observation")
	}
}
