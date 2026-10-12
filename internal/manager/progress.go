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
}

type ProgressResources struct {
	ObservedAt *time.Time `json:"observed_at"`
	Peaks      Peaks      `json:"peaks"`
	DiskScope  string     `json:"disk_scope"`
}

type ProgressLog struct {
	Availability        string     `json:"availability"`
	Bytes               *int64     `json:"bytes"`
	LastOutputAt        *time.Time `json:"last_output_at"`
	QuietSeconds        *int64     `json:"quiet_seconds"`
	TailOffset          int64      `json:"tail_offset"`
	TailBytes           int        `json:"tail_bytes"`
	TailText            string     `json:"tail_text"`
	WindowTruncated     bool       `json:"window_truncated"`
	ChangedDuringRead   bool       `json:"changed_during_read"`
	Provisional         bool       `json:"provisional"`
	TerminalLogRecorded bool       `json:"terminal_log_recorded"`
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
	Availability   string         `json:"availability"`
	Coverage       string         `json:"coverage"`
	Requests       int            `json:"requests_observed"`
	Pending        int            `json:"pending_observed"`
	Completed      int            `json:"completed_observed"`
	Statuses       map[int]int    `json:"completed_status_counts"`
	Events         map[string]int `json:"event_counts"`
	CacheHits      int            `json:"cache_hits_observed"`
	CacheMisses    int            `json:"cache_misses_observed"`
	LastEventAt    *time.Time     `json:"last_event_at"`
	LastTransferAt *time.Time     `json:"last_transfer_at"`
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
		p.Log.TailText = strings.ToValidUTF8(string(b), "\uFFFD")
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
	if b, _, offset, _, err := progressFile(record, "npmproxy.log", progressRegistryWindow, true); err == nil {
		p.Registry = registryProgress(b, offset > 0, now)
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

func registryProgress(b []byte, partial bool, now time.Time) RegistryProgress {
	p := RegistryProgress{Availability: "AVAILABLE", Coverage: "TAIL_WINDOW", Statuses: map[int]int{}, Events: map[string]int{}}
	lines := bytes.Split(b, []byte{'\n'})
	if partial && len(lines) > 0 {
		lines = lines[1:]
	}
	states := map[uint64]string{}
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
		}
		if json.Unmarshal(line, &ev) != nil || ev.Schema != "pomar.npm-request/v1" || ev.Request == 0 {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, ev.Time)
		if err != nil || t.After(now) {
			continue
		}
		t = t.UTC()
		switch ev.Event {
		case "received", "cache", "upstream_started", "upstream_connect_started", "upstream_connected", "upstream_first_byte", "completed":
		default:
			continue
		}
		p.Events[ev.Event]++
		if ev.Event == "cache" {
			if ev.Cache == "hit" {
				p.CacheHits++
			}
			if ev.Cache == "miss" {
				p.CacheMisses++
			}
		}
		if p.LastEventAt == nil || t.After(*p.LastEventAt) {
			p.LastEventAt = &t
		}
		if ev.Event == "upstream_first_byte" || (ev.Event == "completed" && ev.Status >= 200 && ev.Status < 300) {
			if p.LastTransferAt == nil || t.After(*p.LastTransferAt) {
				p.LastTransferAt = &t
			}
		}
		if ev.Event == "received" {
			if _, seen := states[ev.Request]; seen {
				p.Coverage = "REQUEST_ID_REUSE_OBSERVED"
			}
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
	return p
}
