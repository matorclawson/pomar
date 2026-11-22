package notification

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type sinkFunc func(context.Context, Event) error

func (f sinkFunc) Deliver(ctx context.Context, e Event) error { return f(ctx, e) }

func TestEmitIsOptionalAndBounded(t *testing.T) {
	event := Event{ID: "original-1", Workload: "example", Kind: "finished", Message: "job exited"}
	if err := Emit(context.Background(), nil, event); err != nil {
		t.Fatal(err)
	}
	seen := 0
	sink := sinkFunc(func(ctx context.Context, got Event) error {
		seen++
		deadline, ok := ctx.Deadline()
		if got != event || !ok || time.Until(deadline) > maxDeliveryTime {
			t.Fatalf("incorrect event or deadline: %+v, %v", got, deadline)
		}
		return nil
	})
	if err := Emit(context.Background(), sink, event); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Emit(ctx, sink, event); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled event reached delivery: %v", err)
	}
	event.Message = strings.Repeat("x", 4097)
	if err := Emit(context.Background(), sink, event); err == nil || seen != 1 {
		t.Fatal("invalid or cancelled event reached sink")
	}
}
