package zeomessenger

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/rodriveracom/pomar/notification"
)

func TestNotifierUsesScopedOriginalAndRequiresReceipt(t *testing.T) {
	var ids []string
	output := `{"exit":0,"output":"stored"}`
	relay, err := newMailRelay("owner", "workload", "generation", "http://mail.example:7743",
		mailTransport(func(r *http.Request) (*http.Response, error) {
			var body map[string]string
			if r.URL.Path != "/v1/send" || r.Header.Get("X-Zmail-Instance") != "owner" ||
				json.NewDecoder(r.Body).Decode(&body) != nil || body["to"] != "recipient" {
				t.Fatal("delivery lost its scoped binding")
			}
			ids = append(ids, body["request_id"])
			return mailResponse(http.StatusOK, output), nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	notifier := &Notifier{relay: relay, recipient: "recipient"}
	event := notification.Event{ID: "original-1", Workload: "workload", Kind: "done", Message: "command exited"}
	if err := notification.Emit(context.Background(), notifier, event); err != nil {
		t.Fatal(err)
	}
	output = `{"output":"no completed receipt"}`
	if err := notification.Emit(context.Background(), notifier, event); err == nil {
		t.Fatal("accepted a response with no completion receipt")
	}
	if len(ids) != 2 || ids[0] != ids[1] || ids[0] == event.ID || len(ids[0]) != 64 {
		t.Fatalf("retry was not scoped to the same original: %v", ids)
	}
	event.Workload = "different"
	if err := notification.Emit(context.Background(), notifier, event); err == nil || !strings.Contains(err.Error(), "owner binding") || len(ids) != 2 {
		t.Fatal("different workload reached upstream")
	}
}
