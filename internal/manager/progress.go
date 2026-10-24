package manager

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"syscall"
)

const progressLogWindow = 16 << 10
const progressRegistryWindow = 256 << 10

// AttemptProgress is a read-only observation, never a successful-build receipt.
// It is additive on the existing authorized get route, including fixed callers.
type AttemptProgress struct {
	Contract       string            `json:"contract"`
	Attempt        string            `json:"attempt"`
	ManagerKeyID   string            `json:"manager_key_id,omitempty"`
	ObservedAt     time.Time         `json:"observed_at"`
	ElapsedSeconds *int64            `json:"elapsed_seconds"`
	Phase          string            `json:"phase"`
	PhaseSource    string            `json:"phase_source"`
	PhaseSince     *time.Time        `json:"phase_since"`
	Summary        string            `json:"summary"`
	WorkloadPhase  *WorkloadPhase    `json:"workload_phase,omitempty"`
	Log            ProgressLog       `json:"log"`
	Registry       RegistryProgress  `json:"registry"`
	Resources      ProgressResources `json:"resources"`
	// Absence of stdout or a low CPU sample is not proof of a stall.
	StallAssessment string `json:"stall_assessment"`
	// InstallStall is PROFROD-SOW-330/POMAR-CC-SOW-37's own diagnosis,
	// computed on read from the same Log/Registry/times above -- never a
	// verified cause, never retry/config/egress authority.
	InstallStall InstallStallDiagnostic `json:"install_stall"`
}

type ProgressResources struct {
	ObservedAt *time.Time `json:"observed_at"`
	Peaks      Peaks      `json:"peaks"`
	DiskScope  string     `json:"disk_scope"`
}

type ProgressLog struct {
	Availability string     `json:"availability"`
	Bytes        *int64     `json:"bytes"`
	LastOutputAt *time.Time `json:"last_output_at"`
	QuietSeconds *int64     `json:"quiet_seconds"`
	TailOffset   int64      `json:"tail_offset"`
	TailBytes    int        `json:"tail_bytes"`
	TailText     string     `json:"tail_text"`
	// TailTextTruncated describes display-only truncation; raw window metadata is unchanged.
	TailTextTruncated   bool `json:"tail_text_truncated,omitempty"`
	WindowTruncated     bool `json:"window_truncated"`
	ChangedDuringRead   bool `json:"changed_during_read"`
	Provisional         bool `json:"provisional"`
	TerminalLogRecorded bool `json:"terminal_log_recorded"`
}

// WorkloadPhase is an explicit bounded log marker, never a screen inference.
// A job can report a phase; it cannot attest a result or grant rights with it.
type WorkloadPhase struct {
	Phase    string `json:"phase"`
	Sequence int64  `json:"sequence"`
	Source   string `json:"source"`
	Coverage string `json:"coverage"`
}

type RegistryProgress struct {
	Availability string         `json:"availability"`
	Coverage     string         `json:"coverage"`
	Requests     int            `json:"requests_observed"`
	Pending      int            `json:"pending_observed"`
	Completed    int            `json:"completed_observed"`
	Statuses     map[int]int    `json:"completed_status_counts"`
	Events       map[string]int `json:"event_counts"`
	CacheHits    int            `json:"cache_hits_observed"`
	CacheMisses  int            `json:"cache_misses_observed"`
	// FirstEventAt is the first ACCEPTED event encountered in arrival
	// (line) order, not necessarily the lowest timestamp among accepted
	// events (council C8 on #141): an accepted event can itself be a few
	// milliseconds behind the one just before it (ordinary concurrency
	// jitter, within outOfOrderTolerance of the watermark), so a later
	// line can in principle carry an earlier timestamp than the one that
	// already set FirstEventAt. It is never re-sorted or replaced once set.
	FirstEventAt   *time.Time `json:"first_event_at"`
	LastEventAt    *time.Time `json:"last_event_at"`
	LastTransferAt *time.Time `json:"last_transfer_at"`
	// WindowTruncated is this trace read's own partial flag (the window's
	// leading, possibly-cut-off fragment was dropped): install-stall.go's
	// own classification treats this as it would any other observed gap in
	// coverage, never as proof nothing happened before the window started.
	WindowTruncated bool `json:"window_truncated"`
	// LongestGap* names the single largest gap between two consecutive
	// recognized events IN this window (never across requests' own
	// internal retry logic, just event-to-event in arrival order); empty
	// when fewer than two recognized events were observed. Both are this
	// host's own clock (the relay's own time.Now(), the same clock as
	// Entry.Created/Ended and progressFile's file mtimes) -- never a
	// guest-reported time.
	LongestGapSeconds   *int64     `json:"longest_gap_seconds,omitempty"`
	LongestGapFromEvent string     `json:"longest_gap_from_event,omitempty"`
	LongestGapFromAt    *time.Time `json:"longest_gap_from_at,omitempty"`
	LongestGapToEvent   string     `json:"longest_gap_to_event,omitempty"`
	LongestGapToAt      *time.Time `json:"longest_gap_to_at,omitempty"`
	// ShortRequests is at most 3 send_short events, oldest first, each
	// naming the already-redacted route Path npmproxy itself logs (never
	// a raw URL, header or query -- the same redaction Handler already
	// enforces before any of this is written) and the byte/want/reason
	// fields send_short itself carries.
	ShortRequests []ShortRequestEvidence `json:"short_requests,omitempty"`
	// EventsSinceGuestQuiet counts recognized events at or after the
	// guestQuietSince cutoff passed to registryProgress (the guest log's
	// own LastOutputAt) -- a fact a caller can read for itself, not a
	// boolean conclusion this package draws about whose fault a stall is.
	EventsSinceGuestQuiet int `json:"events_since_guest_quiet"`
	// ChangedDuringRead mirrors ProgressLog.ChangedDuringRead for this
	// same npmproxy.log read (council P1-2 on #141: previously computed
	// by progressFile and silently discarded for this source) -- a
	// non-atomic tail read, taken while the file was still being written.
	ChangedDuringRead bool `json:"changed_during_read"`
	// EventsBeforeWindowStart/EventsAfterWindowEnd/EventsOutOfOrder
	// (council P2-2 on #141) count recognized events that fall outside
	// [windowStart, windowEnd] or arrive with a timestamp earlier than an
	// already-accepted one, when registryProgress was given a window to
	// bind against. Such events are facts on their own (a non-zero count
	// is itself worth surfacing) but are excluded from FirstEventAt,
	// LastEventAt, the gap tracking and EventsSinceGuestQuiet -- an event
	// that can't be trusted to belong to this attempt's own timeline
	// must never silently widen or narrow an "observed" gap.
	EventsBeforeWindowStart int `json:"events_before_window_start"`
	EventsAfterWindowEnd    int `json:"events_after_window_end"`
	// EventsOutOfOrder only counts an event whose timestamp is more than
	// outOfOrderTolerance earlier than one already accepted -- council N1:
	// npmproxy stamps time.Now() before acquiring its own log lock, so
	// ordinary concurrent requests (the normal case for a real install,
	// not an edge case) can legitimately land a few milliseconds out of
	// strict order; treating that as corrupted data made a real,
	// concurrent install unable to ever produce an evidential indication.
	EventsOutOfOrder int `json:"events_out_of_order"`
	// EventsInFuture counts a recognized event timestamped after `now`
	// (council N3): previously silently dropped and indistinguishable
	// from a line that simply wasn't there; now a fact in its own right
	// (a clock problem, or a read racing a still-landing write).
	EventsInFuture int `json:"events_in_future"`
}

// outOfOrderTolerance: see EventsOutOfOrder's own doc above.
const outOfOrderTolerance = 1 * time.Second

// ShortRequestEvidence is one send_short event. Path and Reason are
// bounded and sanitized here, at the source, not trusted to upstream
// redaction or left for a caller to bound -- docs/attempt-progress.md's
// own promise ("the registry projection contains aggregates, not raw
// paths") is enforced at the one place that builds this slice, not
// re-derived downstream.
type ShortRequestEvidence struct {
	Request uint64 `json:"request"`
	Path    string `json:"path,omitempty"`
	Bytes   *int64 `json:"bytes,omitempty"`
	Want    *int64 `json:"want,omitempty"`
	// Reason is always one of a closed set (shortReason's own classified
	// buckets, plus sendFile's nil-error short-count message, plus
	// "other" for anything else) -- never raw text passed through.
	Reason string `json:"reason,omitempty"`
	// Truncated is true when Path was shortened, or when Path/Reason
	// contained characters outside a tarball path's own charset and were
	// replaced -- an explicit signal that this entry isn't the log's
	// exact bytes, rather than a silent, unflagged alteration.
	Truncated bool `json:"truncated,omitempty"`
}

// maxShortRequestEvidence bounds ShortRequests: evidence, not a full log replay.
const maxShortRequestEvidence = 3

// maxEvidencePathLen bounds ShortRequestEvidence's Path, applied to the
// already-sanitized (ASCII-printable-only) string: pomar's review found
// npmproxy's own Path has no length bound of its own beyond the log
// line's 4096-byte cap, and a handful of such paths alone could blow past
// this field's own small share of the attempt-progress response.
const maxEvidencePathLen = 200

// evidenceReasons is the closed set a send_short Reason is ever allowed
// to report as: shortReason's own classified buckets (internal/npmproxy),
// plus sendFile's nil-error short-count message, plus "other" for
// anything that doesn't match (never raw text passed through).
var evidenceReasons = map[string]bool{
	"broken pipe": true, "connection reset": true, "connection closed": true,
	"request canceled": true, "deadline exceeded": true, "write failed": true,
	"copy ended with no error short of the file's stated size": true,
}

// sanitizeEvidenceText replaces anything outside printable ASCII with a
// placeholder (so no amount of JSON-escaping-expansion can make a
// bounded-byte-length string marshal larger than a small, predictable
// multiple of its own length -- pomar's U+0001/'<' counterexample),
// then bounds the result to maxLen. The returned bool is true if the
// text was altered in either way.
// jsonEscapes is every byte that doesn't marshal to exactly one byte of
// JSON output -- not just control characters and non-ASCII. Council M08/
// M08b (round five on #141): the first version of this function treated
// any printable-ASCII byte (0x20-0x7e) as already safe, which includes
// '<', '>', '&', '"' and '\\'. Go's encoding/json, by default, HTML-escapes
// '<'/'>'/'&' to six-byte \u00XX sequences, and '"'/'\\' always need a
// two-byte escape -- an all-'<' adversarial path, bounded only by raw
// byte count, still marshaled to well over this report's 4 KiB cap.
// Replacing these five too, alongside the already-excluded control/
// non-ASCII bytes, makes every surviving byte cost exactly one byte in
// the real marshaled output, so the raw-length bound below is an actual
// bound on the escaped size too, regardless of json.Marshal's own
// HTML-escaping setting.
var jsonEscapes = map[byte]bool{'<': true, '>': true, '&': true, '"': true, '\\': true}

func sanitizeEvidenceText(s string, maxLen int) (string, bool) {
	altered := false
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f || c > 0x7e || jsonEscapes[c] {
			out = append(out, '?')
			altered = true
			continue
		}
		out = append(out, c)
	}
	if len(out) > maxLen {
		out = out[:maxLen]
		altered = true
	}
	return string(out), altered
}

// closedEvidence sanitizes and bounds one send_short evidence entry,
// before it's ever stored: the one place this slice is built.
func closedEvidence(e ShortRequestEvidence) ShortRequestEvidence {
	path, pathAltered := sanitizeEvidenceText(e.Path, maxEvidencePathLen)
	e.Path = path
	e.Truncated = pathAltered
	if !evidenceReasons[e.Reason] {
		e.Reason = "other"
	}
	return e
}

// progressFile never follows a record-file symlink or blocks on a FIFO.
// The file is bounded before JSON or log interpretation; replacement and
// truncation cannot turn a read snapshot into signed terminal evidence.
func progressFile(record, name string, limit int64, tail bool) ([]byte, os.FileInfo, int64, bool, error) {
	guard, err := os.OpenFile(record, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, 0, false, err
	}
	defer guard.Close()
	original, err := guard.Stat()
	if err != nil {
		return nil, nil, 0, false, err
	}
	root, err := os.OpenRoot(record)
	if err != nil {
		return nil, nil, 0, false, err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(original, opened) {
		return nil, nil, 0, false, fmt.Errorf("record directory changed")
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, 0, false, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, 0, false, err
	}
	if !fi.Mode().IsRegular() || fi.Size() < 0 {
		return nil, nil, 0, false, fmt.Errorf("not a regular record file")
	}
	if !tail && fi.Size() > limit {
		return nil, nil, 0, false, fmt.Errorf("record exceeds observation limit")
	}
	n := min(fi.Size(), limit)
	offset := int64(0)
	if tail {
		offset = fi.Size() - n
	}
	b := make([]byte, int(n))
	read, err := f.ReadAt(b, offset)
	if err != nil && err != io.EOF {
		return nil, nil, 0, false, err
	}
	after, statErr := f.Stat()
	changed := int64(read) != n || statErr != nil
	if statErr == nil && (after.Size() != fi.Size() || !after.ModTime().Equal(fi.ModTime())) {
		changed = true
	}
	return b[:read], fi, offset, changed, nil
}

func (m *Manager) progressOf(e Entry, now time.Time) *AttemptProgress {
	p := &AttemptProgress{Contract: "pomar.attempt-progress/v1", Attempt: e.Attempt,
		ObservedAt: now.UTC(), PhaseSource: "MANAGER_STATE", Phase: "UNKNOWN",
		Summary: "Current execution phase is not observed.", StallAssessment: "NOT_DETERMINED",
		Log:       ProgressLog{Availability: "UNAVAILABLE", Provisional: true, TerminalLogRecorded: e.Terminal() && e.Log != nil},
		Registry:  RegistryProgress{Availability: "UNAVAILABLE", Coverage: "TAIL_WINDOW", Statuses: map[int]int{}, Events: map[string]int{}},
		Resources: ProgressResources{Peaks: e.Peaks, DiskScope: "SHARED_FILESYSTEM_DELTA_PEAK"}}
	if m.cfg.Signer != nil {
		p.ManagerKeyID = m.cfg.Signer.ID
	}
	end := now
	if e.Terminal() && !e.Ended.IsZero() {
		end = e.Ended
	}
	if !e.Created.IsZero() && !end.Before(e.Created) {
		seconds := int64(end.Sub(e.Created) / time.Second)
		p.ElapsedSeconds = &seconds
	}
	if !e.lastSample.IsZero() && !e.lastSample.After(now) {
		t := e.lastSample.UTC()
		p.Resources.ObservedAt = &t
	}
	switch e.State {
	case StateStarting:
		p.Phase, p.Summary = "STARTING", "Starting the guest; detailed preparation phase is not observed."
	case StateRunning:
		p.Phase, p.Summary = "COMMAND_RUNNING", "Guest command is running; its internal build step is not reported."
	case StateStopping:
		p.Phase, p.Summary = "STOPPING", "Waiting for confirmed guest execution departure."
	}
	record := filepath.Join(m.cfg.Venue.Root(), attemptsDir, e.Attempt)
	if b, _, _, _, err := progressFile(record, "status.json", 64<<10, false); err == nil {
		var st map[string]string
		if json.Unmarshal(b, &st) == nil && st["attempt"] == e.Attempt && st["pid"] == strconv.Itoa(e.PID) {
			phase, summary := helperProgressPhase(st["phase"])
			if phase != "" && !e.Terminal() && e.State != StateStopping {
				p.Phase, p.Summary, p.PhaseSource = phase, summary, "HELPER_STATUS"
				if t, err := time.Parse(time.RFC3339Nano, st["time"]); err == nil && !t.After(now) {
					t = t.UTC()
					p.PhaseSince = &t
				}
			}
		}
	}
	if b, fi, offset, changed, err := progressFile(record, logName, progressLogWindow, true); err == nil {
		size := fi.Size()
		p.Log.Availability, p.Log.Bytes = "AVAILABLE", &size
		p.Log.TailOffset, p.Log.TailBytes = offset, len(b)
		p.Log.WindowTruncated, p.Log.ChangedDuringRead = offset > 0, changed
		p.Log.TailText, p.Log.TailTextTruncated = progressTailText(b)
		if fi.Size() == 0 {
			p.Log.Availability = "NO_OUTPUT_YET"
		}
		if fi.Size() > 0 && !fi.ModTime().After(now) {
			t := fi.ModTime().UTC()
			p.Log.LastOutputAt = &t
			quiet := int64(now.Sub(t) / time.Second)
			p.Log.QuietSeconds = &quiet
		}
		p.WorkloadPhase = workloadPhase(b, offset > 0)
	} else if os.IsNotExist(err) {
		p.Log.Availability = "NOT_CREATED"
	}
	// windowEnd is nil only when this attempt is terminal but never
	// recorded an Ended time -- council P2-1 on #141: that must read as
	// unknown everywhere it's used, never silently fall back to `now`
	// and manufacture a growing fact out of wall-clock time.
	var windowEnd *time.Time
	var windowEndUnknownReason string
	switch {
	case e.Terminal() && e.Ended.IsZero():
		windowEndUnknownReason = "attempt is terminal but recorded no Ended time"
	case e.Terminal():
		end := e.Ended
		windowEnd = &end
	default:
		windowEnd = &now
	}
	if b, _, offset, changed, err := progressFile(record, "npmproxy.log", progressRegistryWindow, true); err == nil {
		p.Registry = registryProgress(b, offset > 0, now, p.Log.LastOutputAt, changed, e.Created, windowEnd)
	} else if os.IsNotExist(err) {
		p.Registry.Availability = "NOT_CREATED"
	}
	if p.Phase == "COMMAND_RUNNING" {
		switch {
		case p.WorkloadPhase != nil:
			p.Summary = "Workload reports: " + workloadSummary(p.WorkloadPhase.Phase) + "."
		case p.Registry.Pending > 0:
			p.Summary = fmt.Sprintf("Guest command is running; %d registry request(s) have no completion in the inspected trace window.", p.Registry.Pending)
		case p.Log.Bytes != nil && *p.Log.Bytes == 0:
			p.Summary = "Guest command is running with no observed stdout/stderr; internal phase and waiting reason are unknown."
		}
	}
	if e.Terminal() {
		p.Phase, p.PhaseSource, p.Summary = "TERMINAL_RECORDED", "MANAGER_STATE", "Manager recorded "+string(e.State)+"; verify the signed result and final log before acting."
		if e.State == StateLost {
			p.Phase, p.Summary = "OUTCOME_UNCONFIRMED", "Helper status was lost; reconcile execution outcome before any retry."
		}
	}
	p.InstallStall = installStallDiagnostic(e.Attempt, p.Registry, p.Log, e.Created, windowEnd, windowEndUnknownReason, now, nil)
	return p
}

func helperProgressPhase(phase string) (string, string) {
	switch phase {
	case "booting":
		return "BOOTING", "Creating and booting the guest."
	case "preparing-inputs":
		return "PREPARING_INPUTS", "Copying the pinned inputs into the guest."
	case "preparing-source":
		return "PREPARING_SOURCE", "Copying and unpacking the pinned source before releasing the command."
	case "running":
		return "COMMAND_RUNNING", "Guest preparation completed; running the submitted command."
	case "exited", "failed", "stopped":
		return "FINALIZING", "Helper reports completion; waiting for the manager's terminal record."
	}
	return "", ""
}

func workloadSummary(phase string) string {
	switch phase {
	case "DEPENDENCIES":
		return "installing dependencies"
	case "VALIDATION":
		return "running checks"
	case "BUILD":
		return "building outputs"
	case "PACKAGING":
		return "packaging outputs"
	case "FINALIZING":
		return "finishing the command"
	}
	return ""
}

func workloadPhase(b []byte, partial bool) *WorkloadPhase {
	lines := bytes.Split(b, []byte{'\n'})
	if partial && len(lines) > 0 {
		lines = lines[1:]
	}
	var latest *WorkloadPhase
	seen := map[int64]string{}
	for _, line := range lines {
		const prefix = "POMAR_PROGRESS_V1 "
		if !bytes.HasPrefix(line, []byte(prefix)) || len(line) > 512 {
			continue
		}
		var marker struct {
			Phase    string `json:"phase"`
			Sequence int64  `json:"sequence"`
		}
		dec := json.NewDecoder(bytes.NewReader(line[len(prefix):]))
		dec.DisallowUnknownFields()
		if dec.Decode(&marker) != nil || dec.Decode(new(any)) != io.EOF || workloadSummary(marker.Phase) == "" || marker.Sequence < 1 || marker.Sequence > 9007199254740991 {
			continue
		}
		if prior, ok := seen[marker.Sequence]; ok && marker.Phase != prior {
			return nil
		}
		seen[marker.Sequence] = marker.Phase
		if latest == nil || marker.Sequence > latest.Sequence {
			latest = &WorkloadPhase{marker.Phase, marker.Sequence, "UNTRUSTED_WORKLOAD_LOG", "TAIL_WINDOW"}
		}
	}
	return latest
}

// windowStart/windowEnd (council P2-2 on #141) bind recognized events to
// the attempt's own timeline: windowEnd nil means the end of that
// timeline isn't known for this read (a terminal attempt with no
// recorded Ended), in which case only windowStart still applies.
func registryProgress(b []byte, partial bool, now time.Time, guestQuietSince *time.Time, changedDuringRead bool, windowStart time.Time, windowEnd *time.Time) RegistryProgress {
	p := RegistryProgress{Availability: "AVAILABLE", Coverage: "TAIL_WINDOW", Statuses: map[int]int{}, Events: map[string]int{}, WindowTruncated: partial, ChangedDuringRead: changedDuringRead}
	lines := bytes.Split(b, []byte{'\n'})
	if partial && len(lines) > 0 {
		lines = lines[1:]
	}
	states := map[uint64]string{}
	// maxAcceptedAt/maxAcceptedName track the highest-timestamp accepted
	// event seen so far (a watermark), never the literal previous line in
	// arrival order. Council N8 (round six on #141): the first version of
	// this check compared against the previous event alone, so a run of
	// small, each-individually-within-tolerance backward steps (e.g. 0.9s
	// at a time, the normal concurrency jitter outOfOrderTolerance exists
	// to absorb) could accumulate unbounded net drift without ever
	// tripping EventsOutOfOrder -- council's own probe: 90s of accumulated
	// backward drift in 0.9s steps, none flagged, then a correct,
	// real-time event arriving afterward computed its gap against the
	// drifted-away previous timestamp instead of the true high point,
	// producing a false REGISTRY_GAP_OVER_THRESHOLD. Comparing against the
	// watermark instead means a genuinely drifting run is itself correctly
	// excluded once it's past tolerance from the highest point actually
	// seen, not merely from whatever its own last (already-drifted) step
	// happened to be.
	var maxAcceptedAt time.Time
	var maxAcceptedName string
	var longestGap time.Duration
	// council P3-3 on #138: a "completed" 2xx is this host's own write
	// already having reported success on the wire before the copy ran; it
	// was never proof the guest received every byte (docs/job-failure-
	// diagnostics.md). shortRequests tracks which request IDs also logged
	// a send_short, so such a request's "completed" line never counts as
	// evidence of a clean transfer here, even though its status is still
	// 2xx. send_short always precedes its request's completed line within
	// the SAME window (the relay writes it from inside serve(), before
	// Handler's own "completed" write).
	//
	// Two refinements (pomar's and council's own review of #139, round
	// three): a reused request ID (the REQUEST_ID_REUSE_OBSERVED case
	// below) must not let a stale entry from the id's PREVIOUS use poison
	// its new one, so a fresh "received" clears it. And this is a bounded
	// TAIL window, not the whole log (progressFile's own partial flag,
	// and this function's own `lines = lines[1:]` above, which drops a
	// possibly-truncated first fragment): a request whose own send_short
	// fell in a dropped-or-never-retained part of the window, while its
	// later completed line is still inside it, would otherwise look
	// identical to one that never had a send_short at all. Any request
	// first observed here via something other than "received" is one this
	// window may have incomplete lifecycle for; treat it as possibly
	// short rather than credit a transfer from an orphaned completion.
	shortRequests := map[uint64]bool{}
	for _, line := range lines {
		if len(line) > 4096 {
			continue
		}
		var ev struct {
			Schema  string `json:"schema"`
			Request uint64 `json:"request"`
			Event   string `json:"event"`
			Time    string `json:"time"`
			Status  int    `json:"status"`
			Cache   string `json:"cache"`
			Path    string `json:"path"`
			Bytes   *int64 `json:"bytes"`
			Want    *int64 `json:"want"`
			Reason  string `json:"reason"`
		}
		if json.Unmarshal(line, &ev) != nil || ev.Schema != "pomar.npm-request/v1" || ev.Request == 0 {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, ev.Time)
		if err != nil {
			continue
		}
		t = t.UTC()
		if t.After(now) {
			// Council N3: a future-stamped event is itself a fact worth
			// surfacing (a clock problem, or a read racing a write that
			// hasn't finished landing), not silently indistinguishable
			// from a line that simply isn't there.
			p.EventsInFuture++
			continue
		}
		switch ev.Event {
		case "received", "cache", "upstream_started", "upstream_connect_started", "upstream_connected", "upstream_first_byte", "send_short", "completed":
		default:
			continue
		}
		_, hadPriorContext := states[ev.Request]
		incompleteCoverage := ev.Event != "received" && !hadPriorContext
		p.Events[ev.Event]++
		if ev.Event == "cache" {
			if ev.Cache == "hit" {
				p.CacheHits++
			}
			if ev.Cache == "miss" {
				p.CacheMisses++
			}
		}
		if ev.Event == "send_short" || incompleteCoverage {
			shortRequests[ev.Request] = true
		}
		if ev.Event == "send_short" && len(p.ShortRequests) < maxShortRequestEvidence {
			p.ShortRequests = append(p.ShortRequests, closedEvidence(ShortRequestEvidence{Request: ev.Request, Path: ev.Path, Bytes: ev.Bytes, Want: ev.Want, Reason: ev.Reason}))
		}
		// An event that can't be trusted to belong to this attempt's own
		// timeline (before it started, after a known end, or arriving
		// with a materially earlier timestamp than one already accepted)
		// is still counted as its own fact, but excluded from every
		// time-based one below it: FirstEventAt/LastEventAt/the gap
		// tracking/EventsSinceGuestQuiet would otherwise silently narrow
		// or widen an "observed" interval using a timestamp this
		// function can't vouch for.
		//
		// Council N1 (round five on #141): npmproxy's own writeEvent
		// calls time.Now() BEFORE acquiring logMu (internal/npmproxy/
		// npmproxy.go), so under real concurrency -- many npm requests
		// in flight at once, the ordinary case for an actual install,
		// not an edge case -- two goroutines can race between stamping
		// their own time and acquiring the lock to write it, letting a
		// line land in the file slightly out of timestamp order relative
		// to one just before it, with NOTHING wrong with either event.
		// A strict t.Before(prevEventAt) check (this function's first
		// version) flagged every such ordinary race as "out of order",
		// which -- combined with a non-zero count being an
		// INSUFFICIENT_EVIDENCE trigger -- meant a real, concurrent
		// install could never produce an evidential indication at all
		// (council's own measurement: 0/60 trials did, at 16 concurrent
		// requests). outOfOrderTolerance absorbs exactly that scheduling
		// jitter without absorbing a genuinely corrupted or reordered
		// log: only a timestamp materially earlier than what's already
		// been accepted -- past the tolerance, not merely a few
		// milliseconds behind it -- counts as out of order.
		beforeStart := !windowStart.IsZero() && t.Before(windowStart)
		afterEnd := windowEnd != nil && t.After(*windowEnd)
		outOfOrder := !maxAcceptedAt.IsZero() && maxAcceptedAt.Sub(t) > outOfOrderTolerance
		if beforeStart {
			p.EventsBeforeWindowStart++
		}
		if afterEnd {
			p.EventsAfterWindowEnd++
		}
		if outOfOrder {
			p.EventsOutOfOrder++
		}
		if !beforeStart && !afterEnd && !outOfOrder {
			if p.FirstEventAt == nil {
				p.FirstEventAt = &t
			}
			if guestQuietSince != nil && !t.Before(*guestQuietSince) {
				p.EventsSinceGuestQuiet++
			}
			if !maxAcceptedAt.IsZero() {
				if gap := t.Sub(maxAcceptedAt); gap > longestGap {
					longestGap = gap
					p.LongestGapFromEvent, p.LongestGapToEvent = maxAcceptedName, ev.Event
					from, to := maxAcceptedAt, t
					p.LongestGapFromAt, p.LongestGapToAt = &from, &to
				}
			}
			if maxAcceptedAt.IsZero() || t.After(maxAcceptedAt) {
				maxAcceptedAt, maxAcceptedName = t, ev.Event
			}
			if p.LastEventAt == nil || t.After(*p.LastEventAt) {
				p.LastEventAt = &t
			}
		}
		if ev.Event == "upstream_first_byte" || (ev.Event == "completed" && ev.Status >= 200 && ev.Status < 300 && !shortRequests[ev.Request]) {
			if p.LastTransferAt == nil || t.After(*p.LastTransferAt) {
				p.LastTransferAt = &t
			}
		}
		if ev.Event == "received" {
			if _, seen := states[ev.Request]; seen {
				p.Coverage = "REQUEST_ID_REUSE_OBSERVED"
			}
			delete(shortRequests, ev.Request) // a fresh use of a reused ID starts with a clean slate
			states[ev.Request] = ev.Event
			continue
		}
		if states[ev.Request] == "completed" {
			continue
		}
		states[ev.Request] = ev.Event
		if ev.Event == "completed" {
			p.Completed++
			p.Statuses[ev.Status]++
		}
	}
	p.Requests = len(states)
	if p.Requests == 0 && len(b) > 0 {
		p.Coverage = "NO_STRUCTURED_EVENTS_OBSERVED"
	}
	for _, state := range states {
		if state != "completed" {
			p.Pending++
		}
	}
	if longestGap > 0 {
		seconds := int64(longestGap / time.Second)
		p.LongestGapSeconds = &seconds
	}
	return p
}

// progressTailText retains the longest valid UTF-8 suffix whose JSON string
// encoding fits the display budget, including quotes and HTML escaping.
// Raw log offsets, phase observations and complete logs keep their original bytes.
func progressTailText(b []byte) (string, bool) {
	text := strings.ToValidUTF8(string(b), "\uFFFD")
	start, encoded := len(text), 2
	for start > 0 {
		r, size := utf8.DecodeLastRuneInString(text[:start])
		cost := size
		switch r {
		case '"', '\\', '\b', '\f', '\n', '\r', '\t':
			cost = 2
		case '<', '>', '&', '\u2028', '\u2029':
			cost = 6
		default:
			if r < 0x20 {
				cost = 6
			}
		}
		if encoded+cost > progressLogWindow {
			break
		}
		encoded += cost
		start -= size
	}
	return text[start:], start > 0
}
