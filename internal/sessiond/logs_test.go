package sessiond

import (
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A session's output is durably logged from creation, whether or not
// anything is ever attached, and is retrievable without attaching.
func TestLogsAreDurableWithoutAttaching(t *testing.T) {
	r := root(t)
	_, c := serve(t, r)
	if err := c.Do("POST", "/v1/sessions", shell("op-log-1", "logme", "printf hello; sleep 30"), &Created{}); err != nil {
		t.Fatal(err)
	}
	waitScreen(t, c, "logme", "hello")
	for end := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		chunk, err := c.RawGet("/v1/sessions/logme/logs")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(chunk.Data), "hello") {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("the log never showed hello: %q", chunk.Data)
		}
	}
}

// The log survives this service ending: a restarted service, which forgets
// every name, can still read what an earlier one captured, by the exact
// session ID.
func TestLogsSurviveARestart(t *testing.T) {
	r := root(t)
	s1, c1 := serve(t, r)
	var created Created
	if err := c1.Do("POST", "/v1/sessions", shell("op-log-2", "logme", "printf durable; sleep 30"), &created); err != nil {
		t.Fatal(err)
	}
	waitScreen(t, c1, "logme", "durable")
	// Give the log goroutine a moment to drain the output event.
	for end := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if b, _ := os.ReadFile(logPath(r, created.ID)); strings.Contains(string(b), "durable") {
			break
		}
		if time.Now().After(end) {
			t.Fatal("the log file never saw the output before restart")
		}
	}
	s1.Close() // stops every session it holds; doesn't delete logs
	s2, c2 := serve(t, r)
	defer s2.Close()
	chunk, err := c2.RawGet("/v1/sessions/by-id/" + created.ID + "/logs")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(chunk.Data), "durable") {
		t.Fatalf("the log didn't survive the restart: %q", chunk.Data)
	}
	// And it isn't reachable by name any more: the new service named nothing yet.
	if err := c2.Do("GET", "/v1/sessions/logme/logs", nil, nil); kindOf(err) != KindNotFound {
		t.Fatalf("a restarted service's by-name lookup: %v", err)
	}
}

// Paging with -from and -limit returns exactly the byte range asked for.
func TestLogsArePaged(t *testing.T) {
	r := root(t)
	_, c := serve(t, r)
	if err := c.Do("POST", "/v1/sessions", shell("op-log-3", "logme", "printf '0123456789'; sleep 30"), &Created{}); err != nil {
		t.Fatal(err)
	}
	waitScreen(t, c, "logme", "0123456789")
	full, err := c.RawGet("/v1/sessions/logme/logs")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(full.Data), "0123456789") {
		t.Fatalf("the full log: %q", full.Data)
	}
	q := url.Values{"from": {"0"}, "limit": {"5"}}
	page, err := c.RawGet("/v1/sessions/logme/logs?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Data) != 5 || !page.Truncated || page.From != 0 {
		t.Fatalf("a 5-byte page: %+v %q", page, page.Data)
	}
	i := strings.Index(string(full.Data), "0123456789")
	q2 := url.Values{"from": {strconv.Itoa(i + 5)}, "limit": {"5"}}
	page2, err := c.RawGet("/v1/sessions/logme/logs?" + q2.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if string(page2.Data) != string(full.Data[i+5:i+10]) {
		t.Fatalf("the second page: got %q, want %q", page2.Data, full.Data[i+5:i+10])
	}
}

// The log's bound is enforced, and recorded once, in the journal, never
// inside the log itself.
func TestLogsAreBounded(t *testing.T) {
	r := root(t)
	s, c := serve(t, r)
	s.logBound = 8 // this instance only: no other test's session races it
	if err := c.Do("POST", "/v1/sessions", shell("op-log-4", "logme", "printf '0123456789abcdef'; sleep 30"), &Created{}); err != nil {
		t.Fatal(err)
	}
	waitScreen(t, c, "logme", "0123456789abcdef")
	var chunk LogChunk
	for end := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		var err error
		if chunk, err = c.RawGet("/v1/sessions/logme/logs"); err != nil {
			t.Fatal(err)
		}
		if chunk.Size >= 8 {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("the log never reached its bound: %+v", chunk)
		}
	}
	if chunk.Size != 8 {
		t.Fatalf("the log grew past its 8-byte bound: %d", chunk.Size)
	}
	// Reading the whole journal confirms the bound was recorded, exactly
	// once, as metadata, never the program's bytes themselves. The journal
	// write follows the log file reaching its bound, so give it a moment.
	var b []byte
	for end := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		var err error
		if b, err = os.ReadFile(r + "/journal.jsonl"); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), `"action":"log-bound"`) || time.Now().After(end) {
			break
		}
	}
	if n := strings.Count(string(b), `"action":"log-bound"`); n != 1 {
		t.Fatalf("the bound was journaled %d times, want exactly once: %s", n, b)
	}
}
