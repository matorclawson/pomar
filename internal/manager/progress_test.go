package manager

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/npmproxy"
)

func TestLiveProgressOnAuthorizedGetDoesNotRequireOrModifyFinalLog(t *testing.T) {
	m, c, v := openSigning(t, false)
	id := "live-progress"
	rec := filepath.Join(v.Root(), attemptsDir, id)
	if err := os.MkdirAll(rec, 0700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	e := terminalEntry(id)
	e.State = StateRunning
	e.ExitCode = nil
	e.PID = 1234
	e.Created = now.Add(-20 * time.Second)
	m.mu.Lock()
	m.t.entries[id] = &e
	m.mu.Unlock()
	st := map[string]string{"attempt": id, "pid": "1234", "phase": "running", "time": now.Add(-5 * time.Second).Format(time.RFC3339Nano)}
	b, _ := json.Marshal(st)
	os.WriteFile(filepath.Join(rec, "status.json"), b, 0600)
	os.WriteFile(filepath.Join(rec, logName), []byte("install started\n"), 0600)
	var got Entry
	if err := c.Do("GET", "/v1/attempts/"+id, nil, &got); err != nil {
		t.Fatal(err)
	}
	p := got.Progress
	if p == nil || p.Contract != "pomar.attempt-progress/v1" || p.Attempt != id || p.Phase != "COMMAND_RUNNING" || p.PhaseSource != "HELPER_STATUS" || p.PhaseSince == nil || p.ElapsedSeconds == nil || *p.ElapsedSeconds < 20 {
		t.Fatalf("progress: %+v", p)
	}
	if p.Log.Availability != "AVAILABLE" || p.Log.TailText != "install started\n" || !p.Log.Provisional || p.Log.TerminalLogRecorded || p.StallAssessment != "NOT_DETERMINED" {
		t.Fatalf("live log: %+v", p)
	}
	if e, _ := m.Get(id); e.Progress != nil || e.Log != nil {
		t.Fatal("GET persisted live evidence or altered final log")
	}
	if _, _, _, err := c.Log(id, nil); err == nil {
		t.Fatal("unsigned live output passed final-log verification")
	}
	code := 0
	m.finish(id, StateExited, "", &code)
	if _, _, _, err := c.Log(id, nil); err != nil {
		t.Fatal(err)
	}
}

func TestQuietAndMissingObservationsStayUnknownNotFailed(t *testing.T) {
	m, _, v := openSigning(t, false)
	id := "quiet-progress"
	rec := filepath.Join(v.Root(), attemptsDir, id)
	os.MkdirAll(rec, 0700)
	e := Entry{Attempt: id, State: StateRunning, PID: 321}
	p := m.progressOf(e, time.Now())
	if p.Log.Availability != "NOT_CREATED" || p.Log.Bytes != nil || p.ElapsedSeconds != nil || p.Resources.ObservedAt != nil || p.StallAssessment != "NOT_DETERMINED" {
		t.Fatalf("invented observations: %+v", p)
	}
	os.WriteFile(filepath.Join(rec, logName), nil, 0600)
	// A status from a different helper must not override this attempt's state.
	os.WriteFile(filepath.Join(rec, "status.json"), []byte(`{"attempt":"quiet-progress","pid":"999","phase":"exited"}`), 0600)
	p = m.progressOf(e, time.Now())
	if p.Phase != "COMMAND_RUNNING" || p.PhaseSource != "MANAGER_STATE" || p.Log.Availability != "NO_OUTPUT_YET" || p.Log.Bytes == nil || *p.Log.Bytes != 0 || p.Log.LastOutputAt != nil || p.StallAssessment != "NOT_DETERMINED" {
		t.Fatalf("quiet is not stalled: %+v", p)
	}
	e.State = StateLost
	p = m.progressOf(e, time.Now())
	if p.Phase != "OUTCOME_UNCONFIRMED" {
		t.Fatalf("missing helper became successful/confirmed departure: %+v", p)
	}
}

func TestProgressIsBoundedAndRejectsFileAndDirectorySymlinks(t *testing.T) {
	rec := t.TempDir()
	data := strings.Repeat("x", progressLogWindow+400) + "last line\n"
	os.WriteFile(filepath.Join(rec, logName), []byte(data), 0600)
	b, fi, offset, changed, err := progressFile(rec, logName, progressLogWindow, true)
	if err != nil || changed || len(b) != progressLogWindow || offset != int64(len(data)-progressLogWindow) || fi.Size() != int64(len(data)) || !strings.HasSuffix(string(b), "last line\n") {
		t.Fatalf("bounded tail: n=%d offset=%d err=%v", len(b), offset, err)
	}
	secret := filepath.Join(t.TempDir(), "outside-canary")
	os.WriteFile(secret, []byte("must-not-be-read"), 0600)
	os.Remove(filepath.Join(rec, logName))
	os.Symlink(secret, filepath.Join(rec, logName))
	if _, _, _, _, err := progressFile(rec, logName, progressLogWindow, true); err == nil {
		t.Fatal("followed a log symlink")
	}
	link := filepath.Join(t.TempDir(), "record-link")
	os.Symlink(rec, link)
	if _, _, _, _, err := progressFile(link, logName, progressLogWindow, true); err == nil {
		t.Fatal("followed a record-directory symlink")
	}
}

func TestProgressDoesNotBroadenClassReaders(t *testing.T) {
	m, _, v := openSigning(t, false)
	id := "private-progress"
	e := terminalEntry(id)
	e.State = StateRunning
	m.mu.Lock()
	m.t.entries[id] = &e
	m.cfg.ClassAllow = map[string][]uint32{e.claimClass().Name: {uint32(m.cfg.UID)}}
	m.mu.Unlock()
	rec := filepath.Join(v.Root(), attemptsDir, id)
	os.MkdirAll(rec, 0700)
	os.WriteFile(filepath.Join(rec, logName), []byte("private-output-canary"), 0600)
	req := httptest.NewRequest("GET", "/v1/attempts/"+id, nil)
	req = req.WithContext(context.WithValue(req.Context(), callerKey{}, caller{known: true, uid: uint32(m.cfg.UID + 1)}))
	w := httptest.NewRecorder()
	m.mux(false).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "private-output-canary") || strings.Contains(w.Body.String(), "tail_text") {
		t.Fatalf("unauthorized progress: %d %s", w.Code, w.Body.String())
	}
}

func TestProgressObservesBlockedRealRegistryRequestBeforeCompletion(t *testing.T) {
	m, _, v := openSigning(t, false)
	id := "registry-progress"
	rec := filepath.Join(v.Root(), attemptsDir, id)
	os.MkdirAll(rec, 0700)
	started, release := make(chan struct{}), make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.Write([]byte("not-the-pinned-package"))
	}))
	defer upstream.Close()
	p := &npmproxy.Proxy{Lock: npmproxy.Lock{"/pkg/-/pkg-1.tgz": strings.Repeat("a", 128)}, Cache: t.TempDir(), Upstream: upstream.URL}
	file, err := os.OpenFile(filepath.Join(rec, "npmproxy.log"), os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.Handler(file).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/pkg/-/pkg-1.tgz", nil))
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("registry request did not start")
	}
	e := Entry{Attempt: id, State: StateRunning}
	obs := m.progressOf(e, time.Now())
	if obs.Registry.Pending != 1 || obs.Registry.Completed != 0 || obs.Registry.Events["received"] != 1 || obs.Registry.CacheMisses != 1 || obs.Registry.Events["upstream_started"] != 1 || obs.Registry.LastTransferAt != nil || !strings.Contains(obs.Summary, "no completion") {
		close(release)
		<-done
		t.Fatalf("blocked request invisible: %+v", obs)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("registry request did not finish")
	}
	obs = m.progressOf(e, time.Now())
	if obs.Registry.Pending != 0 || obs.Registry.Completed != 1 || obs.Registry.Statuses[502] != 1 || obs.Registry.Events["upstream_first_byte"] != 1 {
		t.Fatalf("completion not distinguished: %+v", obs.Registry)
	}
	raw, _ := json.Marshal(obs.Registry)
	if strings.Contains(string(raw), "pkg-") || strings.Contains(string(raw), upstream.URL) {
		t.Fatalf("raw registry paths/addresses exposed: %s", raw)
	}
}

func TestWorkloadMarkersAreExplicitBoundedUntrustedAndWindowed(t *testing.T) {
	b := []byte("random screen says build done\nPOMAR_PROGRESS_V1 {\"phase\":\"DEPENDENCIES\",\"sequence\":1}\nPOMAR_PROGRESS_V1 {\"phase\":\"BUILD\",\"sequence\":2}\n")
	p := workloadPhase(b, false)
	if p == nil || p.Phase != "BUILD" || p.Sequence != 2 || p.Source != "UNTRUSTED_WORKLOAD_LOG" {
		t.Fatalf("explicit marker: %+v", p)
	}
	for _, bad := range []string{`{"phase":"SUCCESS","sequence":3}`, `{"phase":"BUILD","sequence":0}`, `{"phase":"BUILD","sequence":3,"grant":"admin"}`, `{"phase":"BUILD","sequence":3} true`} {
		if got := workloadPhase([]byte("POMAR_PROGRESS_V1 "+bad), false); got != nil {
			t.Fatalf("accepted invalid marker %s: %+v", bad, got)
		}
	}
	if got := workloadPhase([]byte("POMAR_PROGRESS_V1 {\"phase\":\"BUILD\",\"sequence\":3}"), true); got != nil {
		t.Fatal("interpreted first partial line")
	}
	conflict := fmt.Sprintf("POMAR_PROGRESS_V1 {\"phase\":\"BUILD\",\"sequence\":2}\nPOMAR_PROGRESS_V1 {\"phase\":\"PACKAGING\",\"sequence\":2}\n")
	if got := workloadPhase([]byte(conflict), false); got != nil {
		t.Fatalf("accepted conflicting phase: %+v", got)
	}
}

// failAfterWriter is an http.ResponseWriter whose Write fails once allow
// bytes have gone out, simulating a client/tunnel that stops reading
// partway through -- the same shape npmproxy's own send_short tests use.
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
		return 0, fmt.Errorf("broken pipe (fake)")
	}
	n := len(p)
	if n > remaining {
		n = remaining
	}
	w.written += n
	if n < len(p) {
		return n, fmt.Errorf("broken pipe (fake)")
	}
	return n, nil
}

// council P3-3 on #138: this package's own registry-progress reader
// silently dropped send_short lines entirely (not in the switch that
// decides which events are even counted) and treated every 2xx
// "completed" as proof of a clean transfer, regardless of whether the
// same request also logged a send_short -- exactly the gap
// docs/job-failure-diagnostics.md names: the status line is already on
// the wire before the body copy can fail, so a 2xx completed line alone
// is this host's own write succeeding, never the guest's receipt. This
// drives a real cache-hit request through a writer that fails partway,
// producing a genuine send_short alongside its 2xx completed line, and
// checks that this reader neither drops the event nor counts that
// request's completion as evidence of a transfer.
func TestRegistryProgressNeverCountsASendShortCompletionAsATransfer(t *testing.T) {
	m, _, v := openSigning(t, false)
	id := "registry-progress-short"
	rec := filepath.Join(v.Root(), attemptsDir, id)
	os.MkdirAll(rec, 0700)

	cacheDir := t.TempDir()
	sum := strings.Repeat("b", 128)
	content := bytes.Repeat([]byte("x"), 1000)
	if err := os.WriteFile(filepath.Join(cacheDir, sum), content, 0o600); err != nil {
		t.Fatal(err)
	}
	p := &npmproxy.Proxy{Lock: npmproxy.Lock{"/pkg/-/pkg-1.tgz": sum}, Cache: cacheDir}

	file, err := os.OpenFile(filepath.Join(rec, "npmproxy.log"), os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	w := &failAfterWriter{allow: 100}
	p.Handler(file).ServeHTTP(w, httptest.NewRequest("GET", "/pkg/-/pkg-1.tgz", nil))

	e := Entry{Attempt: id, State: StateRunning}
	obs := m.progressOf(e, time.Now())
	if obs.Registry.Events["send_short"] != 1 {
		t.Fatalf("send_short must be observed, not silently dropped: %+v", obs.Registry)
	}
	if obs.Registry.Completed != 1 || obs.Registry.Statuses[200] != 1 {
		t.Fatalf("the completed 2xx line should still be observed as a completion: %+v", obs.Registry)
	}
	if obs.Registry.LastTransferAt != nil {
		t.Fatalf("a completed 2xx alongside a send_short for the same request must not be counted as a transfer: %+v", obs.Registry)
	}
}

// pomar's review of #139 (round three, maintainer source review): a
// bounded tail window can retain a request's "completed" 2xx line while
// its own send_short fell in the dropped-or-untruncated-away first
// fragment (progressFile's partial read drops exactly one leading,
// possibly-truncated line). shortRequests would then have no entry for
// that request, so its orphaned completion would be credited as a
// transfer -- exactly the false-positive this package exists to avoid.
// This drives registryProgress directly with partial=true and a window
// whose only evidence for a request is its own completed line, no
// received/cache/send_short visible at all, matching pomar's named
// fixture precisely.
func TestRegistryProgressTreatsAnOrphanedCompletionInATruncatedWindowAsPossiblyShort(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	// The first line is a truncated fragment of the real send_short line
	// that fell outside the retained window -- partial=true means
	// registryProgress itself drops it, same as it always does for a tail
	// read's possibly-cut-off leading line. What's left after that drop
	// is exactly the orphaned completed line pomar's fixture names: no
	// received/cache/send_short visible for request 7 at all.
	log := strings.Join([]string{
		`e":false,"status":200,"bytes":0,"want":1000,"reason":"write failed"}`, // the dropped, truncated fragment
		`{"schema":"pomar.npm-request/v1","request":7,"event":"completed","time":"2026-10-17T11:59:59Z","status":200}`,
	}, "\n") + "\n"
	p := registryProgress([]byte(log), true, now)
	if p.Completed != 1 || p.Statuses[200] != 1 {
		t.Fatalf("the observed completion/status counters must still be preserved: %+v", p)
	}
	if p.LastTransferAt != nil {
		t.Fatalf("an orphaned completion in a truncated window, with no in-window evidence it was clean, must not be credited as a transfer: %+v", p)
	}
}

// council P3 on #139 (round three): shortRequests was never cleared on a
// fresh "received", so a request ID reused for a second, genuinely clean
// transfer after an earlier short one would still have its clean
// completion wrongly suppressed by the first use's stale entry.
func TestRegistryProgressClearsShortRequestsOnAReusedRequestID(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	log := strings.Join([]string{
		`{"schema":"pomar.npm-request/v1","request":9,"event":"received","time":"2026-10-17T11:00:00Z"}`,
		`{"schema":"pomar.npm-request/v1","request":9,"event":"send_short","time":"2026-10-17T11:00:01Z","status":200,"bytes":10}`,
		`{"schema":"pomar.npm-request/v1","request":9,"event":"completed","time":"2026-10-17T11:00:01Z","status":200}`,
		`{"schema":"pomar.npm-request/v1","request":9,"event":"received","time":"2026-10-17T11:00:02Z"}`,
		`{"schema":"pomar.npm-request/v1","request":9,"event":"completed","time":"2026-10-17T11:00:03Z","status":200}`,
	}, "\n") + "\n"
	p := registryProgress([]byte(log), false, now)
	if p.Coverage != "REQUEST_ID_REUSE_OBSERVED" {
		t.Fatalf("a reused request ID should be flagged: %+v", p)
	}
	if p.LastTransferAt == nil {
		t.Fatalf("the reused ID's second, genuinely clean completion must be credited as a transfer, not suppressed by the first use's stale send_short: %+v", p)
	}
}
