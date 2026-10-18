package manager

import "time"

// InstallStallDiagnostic answers, from already-captured bounded evidence
// only, where an attempt's time went during an install -- never a verified
// root cause, never retry/config/egress authority, and never a replacement
// for the signed final result. It is computed on read, the same
// authorization as the rest of AttemptProgress, from sources that already
// exist and are already bounded: the guest log tail (progressLogWindow),
// the registry trace (progressRegistryWindow, via the reviewed
// registryProgress parser, extended in place rather than re-parsed here),
// status.json's phase markers, and the attempt's own recorded times. It
// introduces no new guest-side capture, no new file and no new socket.
//
// Design reviewed by the council (zc-pcc-collector-v1, ADEQUATE TO BUILD,
// five amendments, all folded in here):
//  1. every class's own boolean is always reported, not just the chosen
//     Classification, so a reader can see a lower-precedence class was
//     also true; a truncated window can never read NO_STALL_OBSERVED.
//  2. the gap threshold is never silently hardcoded without saying so;
//     ThresholdSource names whether it came from a recorded value or
//     this package's own default.
//  3. the gap analysis covers the start (Created -> first event) and end
//     (last event -> Ended, or -> ObservedAt while still running) edges,
//     not just gaps between events; every timestamp here is the HOST's
//     own clock (the relay's time.Now(), the same clock as Entry.Created/
//     Ended and progressFile's file mtimes) -- never a guest-reported time
//     subtracted against a host one.
//  4. GUEST_QUIET_NO_REGISTRY_ACTIVITY is defined precisely: the guest's
//     own output has been quiet for at least the threshold WHILE the
//     registry trace shows an event after that quiet period started --
//     i.e. something is still happening that the guest's own stdout
//     doesn't show, so the stall isn't attributable to the registry proxy.
//  5. this never writes into the attempt's own record directory (that
//     stays exactly status.json/npmproxy.log/the guest log, never touched
//     here) and never returns anything beyond what progressOf's existing
//     reads already produced -- no new file, no new redaction surface.
type InstallStallDiagnostic struct {
	Contract       string    `json:"contract"`
	Attempt        string    `json:"attempt"`
	ObservedAt     time.Time `json:"observed_at"`
	ElapsedSeconds *int64    `json:"elapsed_seconds"`
	// ClockSource is always "host": documents amendment 3 in the output
	// itself, not just in this comment.
	ClockSource string `json:"clock_source"`

	// Classification is exactly one of the five below, by fixed
	// precedence (highest first): ProxyDeliveryShort,
	// RegistryGapExceedsThreshold, GuestQuietNoRegistryActivity,
	// WindowTruncated, else NoStallObserved. Every boolean is still
	// reported regardless of which one was chosen.
	Classification string `json:"classification"`

	ProxyDeliveryShort           bool `json:"proxy_delivery_short"`
	RegistryGapExceedsThreshold  bool `json:"registry_gap_exceeds_threshold"`
	GuestQuietNoRegistryActivity bool `json:"guest_quiet_no_registry_activity"`
	WindowTruncated              bool `json:"window_truncated"`

	ThresholdSeconds int64  `json:"threshold_seconds"`
	ThresholdSource  string `json:"threshold_source"` // "recorded" or "default"

	// The single largest gap found, across the registry window's own
	// internal event-to-event gap and the two edges (Created -> first
	// event, last event -> Ended/ObservedAt). From/To name "attempt_created"
	// and "attempt_ended"/"observed_at" for the edges, or the two npm-
	// request event names for an internal gap.
	GapSeconds *int64     `json:"gap_seconds,omitempty"`
	GapFrom    string     `json:"gap_from,omitempty"`
	GapFromAt  *time.Time `json:"gap_from_at,omitempty"`
	GapTo      string     `json:"gap_to,omitempty"`
	GapToAt    *time.Time `json:"gap_to_at,omitempty"`

	GuestQuietSeconds *int64 `json:"guest_quiet_seconds,omitempty"`

	SendShortCount    int                    `json:"send_short_count"`
	SendShortRequests []ShortRequestEvidence `json:"send_short_requests,omitempty"`
}

// defaultFetchTimeoutSeconds is this package's own fallback, not a
// recorded value: no existing status.json or Entry field names the
// install's actual fetch-timeout today (a named gap, not hidden -- see
// ThresholdSource). It matches npm's own conventional default and the
// value profrod's own install-locked-v1.mjs configures.
const defaultFetchTimeoutSeconds = 60

const (
	stallProxyDeliveryShort = "PROXY_DELIVERY_SHORT"
	stallRegistryGap        = "REGISTRY_GAP_EXCEEDS_FETCH_TIMEOUT"
	stallGuestQuiet         = "GUEST_QUIET_NO_REGISTRY_ACTIVITY"
	stallWindowTruncated    = "INCONCLUSIVE_WINDOW_TRUNCATED"
	stallNoneObserved       = "NO_STALL_OBSERVED"
)

// installStallDiagnostic is pure: every input is already read and bounded
// by progressOf's own calls; this only classifies what they produced.
// recordedFetchTimeoutSeconds is nil until some future status.json field
// actually records it; today ThresholdSource is always "default".
func installStallDiagnostic(attempt string, reg RegistryProgress, log ProgressLog, created, ended time.Time, terminal bool, now time.Time, recordedFetchTimeoutSeconds *int64) InstallStallDiagnostic {
	d := InstallStallDiagnostic{
		Contract:    "pomar.install-stall-diagnostic/v1",
		Attempt:     attempt,
		ObservedAt:  now.UTC(),
		ClockSource: "host",
	}
	if !created.IsZero() {
		end := now
		if terminal && !ended.IsZero() {
			end = ended
		}
		if !end.Before(created) {
			seconds := int64(end.Sub(created) / time.Second)
			d.ElapsedSeconds = &seconds
		}
	}

	d.ThresholdSeconds, d.ThresholdSource = int64(defaultFetchTimeoutSeconds), "default"
	if recordedFetchTimeoutSeconds != nil {
		d.ThresholdSeconds, d.ThresholdSource = *recordedFetchTimeoutSeconds, "recorded"
	}

	d.SendShortCount = reg.Events["send_short"]
	d.SendShortRequests = reg.ShortRequests
	d.ProxyDeliveryShort = d.SendShortCount > 0

	d.WindowTruncated = reg.WindowTruncated || log.WindowTruncated

	// The overall gap: the registry window's own largest internal gap,
	// plus the two edges this function adds. Each edge needs both ends
	// to exist; an edge this function can't compute (no recognized event
	// at all) is simply absent, not assumed zero.
	trackGap := func(seconds int64, from string, fromAt time.Time, to string, toAt time.Time) {
		if d.GapSeconds == nil || seconds > *d.GapSeconds {
			d.GapSeconds, d.GapFrom, d.GapFromAt, d.GapTo, d.GapToAt = &seconds, from, &fromAt, to, &toAt
		}
	}
	if reg.LongestGapSeconds != nil {
		trackGap(*reg.LongestGapSeconds, reg.LongestGapFromEvent, *reg.LongestGapFromAt, reg.LongestGapToEvent, *reg.LongestGapToAt)
	}
	if reg.FirstEventAt != nil && !created.IsZero() && !reg.FirstEventAt.Before(created) {
		trackGap(int64(reg.FirstEventAt.Sub(created)/time.Second), "attempt_created", created, "first_registry_event", *reg.FirstEventAt)
	}
	if reg.LastEventAt != nil {
		end, endLabel := now, "observed_at"
		if terminal && !ended.IsZero() {
			end, endLabel = ended, "attempt_ended"
		}
		if !end.Before(*reg.LastEventAt) {
			trackGap(int64(end.Sub(*reg.LastEventAt)/time.Second), "last_registry_event", *reg.LastEventAt, endLabel, end)
		}
	}
	if d.GapSeconds != nil && *d.GapSeconds > d.ThresholdSeconds {
		d.RegistryGapExceedsThreshold = true
	}

	if log.QuietSeconds != nil {
		d.GuestQuietSeconds = log.QuietSeconds
		if *log.QuietSeconds >= d.ThresholdSeconds && log.LastOutputAt != nil && reg.LastEventAt != nil && reg.LastEventAt.After(*log.LastOutputAt) {
			d.GuestQuietNoRegistryActivity = true
		}
	}

	switch {
	case d.ProxyDeliveryShort:
		d.Classification = stallProxyDeliveryShort
	case d.RegistryGapExceedsThreshold:
		d.Classification = stallRegistryGap
	case d.GuestQuietNoRegistryActivity:
		d.Classification = stallGuestQuiet
	case d.WindowTruncated:
		d.Classification = stallWindowTruncated
	default:
		d.Classification = stallNoneObserved
	}
	return d
}
