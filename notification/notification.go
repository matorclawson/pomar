// Package notification defines optional, owner-controlled workload notifications.
package notification

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"time"
	"unicode/utf8"
)

const maxDeliveryTime = 15 * time.Second

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Event carries an original operation ID and bounded public text. Delivery does
// not imply workload completion or give the receiver authority over a workload.
type Event struct {
	ID       string
	Workload string
	Kind     string
	Message  string
}

type Sink interface {
	Deliver(context.Context, Event) error
}

func (event Event) Validate() error {
	if !identifier.MatchString(event.ID) || !identifier.MatchString(event.Workload) ||
		!identifier.MatchString(event.Kind) || len(event.Message) == 0 ||
		len(event.Message) > 4096 || !utf8.ValidString(event.Message) {
		return errors.New("invalid bounded notification event")
	}
	return nil
}

// Emit validates before invoking an explicitly provided sink. A timeout is an
// uncertain delivery. A caller that retries must reuse the same event ID.
func Emit(ctx context.Context, sink Sink, event Event) error {
	if err := event.Validate(); err != nil {
		return err
	}
	if sink == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, maxDeliveryTime)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	return sink.Deliver(ctx, event)
}

// Binding is selected by the owner. It cannot be supplied by the guest.
type Binding struct {
	Identity, Environment, Incarnation string
}

// Channel is a revocable optional guest endpoint. Its interpretation is owned
// by the integration. The core owns its local listener and lifetime.
type Channel interface {
	http.Handler
	Name() string
	Revoke()
}

// OpenChannel receives an opaque owner-configured route for a specific binding.
type OpenChannel func(binding Binding, route string) (Channel, error)
