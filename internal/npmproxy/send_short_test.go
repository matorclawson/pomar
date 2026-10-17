package npmproxy

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// failAfterWriter is an http.ResponseWriter whose Write fails once allow
// bytes have gone out, simulating a client/tunnel that stops reading
// partway through a response — exactly the gap PROFROD-SOW-330/pomar#83
// named: io.Copy's error, previously discarded, must now be reported.
type failAfterWriter struct {
	header  http.Header
	allow   int
	written int
}

func (w *failAfterWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *failAfterWriter) WriteHeader(int) {}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	remaining := w.allow - w.written
	if remaining <= 0 {
		return 0, errors.New("broken pipe (fake)")
	}
	n := len(p)
	if n > remaining {
		n = remaining
	}
	w.written += n
	if n < len(p) {
		return n, errors.New("broken pipe (fake)")
	}
	return n, nil
}

type recordedEvent struct {
	Event, Reason string
	Bytes         int64
}

// A send that falls short of the file's full length — whether io.Copy
// returns an error, or (defensively) doesn't but still wrote less than the
// file's size — reports send_short with the real byte count and a reason,
// never just silently folding into a 200 "completed" as if the guest got
// everything.
func TestSendFileReportsSendShortOnAWriteFailure(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/tarball"
	content := make([]byte, 10000)
	for i := range content {
		content[i] = byte(i)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := &failAfterWriter{allow: 100}
	var events []recordedEvent
	writeEvent := func(event, cache string, status int, bytes int64, reason string) {
		events = append(events, recordedEvent{event, reason, bytes})
	}
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	status, n, hit := sendFile(w, r, f, false, writeEvent)

	// The status line was already written before the copy could fail:
	// HTTP has no way to revise it afterward. This is the exact, honestly
	// named limit — the repair is in what gets logged, not in retracting
	// a response already on the wire.
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (already committed before the write failed)", status)
	}
	if hit {
		t.Fatal("hit should reflect what the caller passed, not be invented here")
	}
	if n != 100 {
		t.Fatalf("the returned byte count should be exactly what was actually written: got %d, want 100", n)
	}

	var short *recordedEvent
	for i := range events {
		if events[i].Event == "send_short" {
			short = &events[i]
		}
	}
	if short == nil {
		t.Fatalf("a short write must report send_short, not go unnoticed: events=%+v", events)
	}
	if short.Bytes != 100 {
		t.Fatalf("send_short's bytes = %d, want 100 (not the file's full 10000, and not 0)", short.Bytes)
	}
	if short.Reason == "" {
		t.Fatal("send_short must carry a reason, not an empty one")
	}
	if short.Reason != "write failed" {
		// A plain errors.New from the fake writer matches no classified
		// syscall/net/context case, so it must fall through to the generic
		// bucket -- never the raw err.Error() text (profrod's R3: this
		// package redacts everything else in the log; a write error's
		// text isn't something it controls the contents of either).
		t.Fatalf(`reason = %q, want the generic "write failed" bucket for an unclassified error`, short.Reason)
	}
}

// The nil-error short-count branch (want >= 0 && n != want) is a genuinely
// different path from a write failure: io.Copy can return no error at all
// and still have copied fewer bytes than Stat promised, if the reader runs
// dry early. A failing writer, like the one above, always returns a
// non-nil error on a short write and never reaches this branch -- pomar's
// own review caught that my first claim to have covered this case was
// wrong. Advancing the read cursor past where Stat already measured the
// file's size exercises it deterministically, with no goroutines, timing
// or real I/O failure involved: Stat reports the file's full size
// regardless of the current offset, so the copy cleanly hits EOF having
// read only what's left from here on.
func TestSendFileReportsSendShortOnANilErrorShortCount(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/tarball"
	content := make([]byte, 100)
	for i := range content {
		content[i] = byte(i)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Seek(60, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	var events []recordedEvent
	writeEvent := func(event, cache string, status int, bytes int64, reason string) {
		events = append(events, recordedEvent{event, reason, bytes})
	}
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	status, n, _ := sendFile(rec, r, f, false, writeEvent)
	if status != http.StatusOK || n != 40 {
		t.Fatalf("status=%d n=%d, want 200 40 (the 40 bytes actually left to read from offset 60)", status, n)
	}

	var short *recordedEvent
	for i := range events {
		if events[i].Event == "send_short" {
			short = &events[i]
		}
	}
	if short == nil {
		t.Fatal("a clean-EOF short copy must still report send_short, not go unnoticed just because io.Copy returned no error")
	}
	if short.Bytes != 40 {
		t.Fatalf("send_short bytes = %d, want 40", short.Bytes)
	}
	if short.Reason == "" {
		t.Fatal("send_short must carry a reason even without an io.Copy error")
	}
}

// A clean, complete send reports no send_short event at all.
func TestSendFileReportsNothingExtraOnACleanSend(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/tarball"
	content := []byte("a whole, uninterrupted tarball")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	rec := httptest.NewRecorder()
	var events []recordedEvent
	writeEvent := func(event, cache string, status int, bytes int64, reason string) {
		events = append(events, recordedEvent{event, reason, bytes})
	}
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	status, n, _ := sendFile(rec, r, f, false, writeEvent)
	if status != http.StatusOK || n != int64(len(content)) {
		t.Fatalf("a clean send should report the full byte count: status=%d n=%d, want 200 %d", status, n, len(content))
	}
	for _, e := range events {
		if e.Event == "send_short" {
			t.Fatalf("a clean, complete send must never report send_short: %+v", events)
		}
	}
}

// HEAD returns before io.Copy ever runs: there is no body to fall short of,
// so send_short can never fire for one, and its absence here proves
// nothing about a body that was never sent in the first place.
func TestSendFileNeverReportsSendShortOnHEAD(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/tarball"
	content := []byte("a whole, uninterrupted tarball")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := &failAfterWriter{allow: 0} // would fail on the very first body byte, if any were written
	var events []recordedEvent
	writeEvent := func(event, cache string, status int, bytes int64, reason string) {
		events = append(events, recordedEvent{event, reason, bytes})
	}
	r := httptest.NewRequest(http.MethodHead, "/x", nil)
	status, n, _ := sendFile(w, r, f, false, writeEvent)
	if status != http.StatusOK || n != 0 {
		t.Fatalf("HEAD should report 200 and zero bytes: status=%d n=%d", status, n)
	}
	if len(events) != 0 {
		t.Fatalf("HEAD should write no events at all from sendFile: %+v", events)
	}
}
