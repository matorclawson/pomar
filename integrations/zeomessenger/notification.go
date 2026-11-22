package zeomessenger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/rodriveracom/pomar/notification"
)

// Notifier delivers bounded owner events to one configured mailbox. It uses
// the same scoped retry keys, origin policy and budgets as the guest relay.
type Notifier struct {
	relay     *mailRelay
	recipient string
}

func NewNotifier(binding notification.Binding, origin, recipient string) (*Notifier, error) {
	if !mailID.MatchString(recipient) {
		return nil, errors.New("invalid notification recipient")
	}
	relay, err := newMailRelay(binding.Identity, binding.Environment, binding.Incarnation, origin, nil)
	if err != nil {
		return nil, err
	}
	return &Notifier{relay: relay, recipient: recipient}, nil
}

func (n *Notifier) Revoke() { n.relay.Revoke() }

func (n *Notifier) Deliver(ctx context.Context, event notification.Event) error {
	if err := event.Validate(); err != nil {
		return err
	}
	if event.Workload != n.relay.guest {
		return errors.New("notification workload differs from owner binding")
	}
	body, err := json.Marshal(map[string]string{
		"to": n.recipient, "subject": event.Kind, "body": event.Message, "request_id": event.ID,
	})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/send", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response := &localResponse{header: make(http.Header)}
	n.relay.ServeHTTP(response, request)
	var receipt struct {
		Exit *int `json:"exit"`
	}
	if response.status < 200 || response.status >= 300 ||
		json.Unmarshal(response.body.Bytes(), &receipt) != nil || receipt.Exit == nil || *receipt.Exit != 0 {
		return errors.New("notification delivery unconfirmed")
	}
	return nil
}

// This response only receives the relay's bounded in-memory output. Its input
// body is already in memory, so a socket read deadline is unnecessary.
type localResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *localResponse) Header() http.Header             { return r.header }
func (r *localResponse) WriteHeader(status int)          { r.status = status }
func (r *localResponse) SetReadDeadline(time.Time) error { return nil }
func (r *localResponse) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(p)
}
