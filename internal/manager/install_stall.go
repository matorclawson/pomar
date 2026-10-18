package manager

import (
	"encoding/json"
	"time"
)

// Source status: whether a given evidence source (the guest log, the
// registry trace) was actually readable and parseable for this read.
const (
	sourceOK          = "ok"
	sourceUnknown     = "unknown"
	sourceUnavailable = "unavailable"
)

// maxReportBytes is this report's own documented cap, enforced on the
// actual marshaled bytes (council P1-3 on #141: bounding fields before
// JSON-escaping, or asserting a cap without ever measuring the real
// serialization, isn't enforcement) -- never assumed from field shapes.
const maxReportBytes = 4 << 10

// InstallStallDiagnostic is a FACT-ONLY report of what's already recorded
// about one attempt's install, for PROFROD-SOW-330/POMAR-CC-SOW-37 --
// never a verified cause, never retry/config/egress authority, never a
// replacement for the signed final result. It is computed on read, behind
// the same authorization as the rest of AttemptProgress, from sources
// already read and bounded elsewhere in this package (the guest log tail,
// the registry trace via registryProgress -- extended in place, not
// re-parsed -- status.json and the attempt's own recorded times). It
// introduces no new guest-side capture, no new file and no new socket,
// and writes nothing into the attempt's own record directory.
//
// Council's arbitration (zc-pcc-collector-v1 amendment 1, after pomar's
// review): the first version of this type named classes causally
// (REGISTRY_GAP_EXCEEDS_FETCH_TIMEOUT, GUEST_QUIET_NO_REGISTRY_ACTIVITY)
// from evidence that can't actually support that certainty. Every
// measured value below is a fact plus its own source status; every
// optional numeric fact is still SERIALIZED (null, not omitted) when
// unknown, paired with its own *_unknown_reason (council P1-4 on #141 --
// round two's omitempty made an unknown fact indistinguishable from one
// that was never measured at all). Indication is OPTIONAL and
// evidential-named, by a fixed precedence in which INSUFFICIENT_EVIDENCE
// is checked FIRST and wins outright whenever it applies -- round two had
// it last, so a truncated or unknown source sitting alongside a genuine
// gap still read as a confident REGISTRY_GAP_OVER_THRESHOLD (council
// P1-1); every fact still appears in the document regardless of which
// Indication won, so a reader can always see what else was true.
type InstallStallDiagnostic struct {
	Contract    string    `json:"contract"`
	Attempt     string    `json:"attempt"`
	ObservedAt  time.Time `json:"observed_at"`
	ClockSource string    `json:"clock_source"` // always "host"

	ElapsedSeconds       *int64 `json:"elapsed_seconds"`
	ElapsedUnknownReason string `json:"elapsed_unknown_reason,omitempty"`

	LogStatus          string `json:"log_status"` // ok | unknown | unavailable
	LogStatusReason    string `json:"log_status_reason,omitempty"`
	LogWindowTruncated bool   `json:"log_window_truncated"`

	RegistryStatus            string `json:"registry_status"` // ok | unknown | unavailable
	RegistryStatusReason      string `json:"registry_status_reason,omitempty"`
	RegistryWindowTruncated   bool   `json:"registry_window_truncated"`
	RegistryChangedDuringRead bool   `json:"registry_changed_during_read"`

	// Events this function can't bind to the attempt's own timeline
	// (council P2-2): a non-zero count here is itself a fact, and is why
	// none of the time-based facts below ever include such an event.
	EventsBeforeWindowStart int `json:"events_before_window_start"`
	EventsAfterWindowEnd    int `json:"events_after_window_end"`
	EventsOutOfOrder        int `json:"events_out_of_order"`

	SendShortCount    int                    `json:"send_short_count"`
	SendShortRequests []ShortRequestEvidence `json:"send_short_requests,omitempty"`
	// EvidenceTruncated is set if SendShortRequests had to be dropped
	// entirely to keep this report's own marshaled bytes under
	// maxReportBytes -- a last-resort guard, not expected to trigger
	// given the bounds already applied to each entry (see
	// ShortRequestEvidence.Truncated for the common, per-entry case).
	EvidenceTruncated bool `json:"evidence_truncated,omitempty"`

	// The registry window's own single largest gap between two
	// consecutive recognized events (never the start edge, which is
	// excluded entirely when the window is truncated -- P2-3 -- and
	// never the end edge, which is a separate, explicitly-named fact
	// below, not folded into this one to avoid conflating "an internal
	// gap we actually observed" with "silence since the last thing we
	// saw, of unknown duration going forward").
	LongestRegistryGapSeconds       *int64     `json:"longest_registry_gap_seconds"`
	LongestRegistryGapUnknownReason string     `json:"longest_registry_gap_unknown_reason,omitempty"`
	LongestRegistryGapFromEvent     string     `json:"longest_registry_gap_from_event,omitempty"`
	LongestRegistryGapFromAt        *time.Time `json:"longest_registry_gap_from_at,omitempty"`
	LongestRegistryGapToEvent       string     `json:"longest_registry_gap_to_event,omitempty"`
	LongestRegistryGapToAt          *time.Time `json:"longest_registry_gap_to_at,omitempty"`

	// The end edge: the last recognized registry event to the attempt's
	// own window end (Ended, or ObservedAt while still running). Named
	// separately from the internal gap above. Unknown when the window
	// end itself is unknown (a terminal attempt with no recorded Ended),
	// never computed against `now` in that case (council P2-1).
	TrailingRegistrySilenceSeconds       *int64     `json:"trailing_registry_silence_seconds"`
	TrailingRegistrySilenceUnknownReason string     `json:"trailing_registry_silence_unknown_reason,omitempty"`
	TrailingRegistrySilenceSinceAt       *time.Time `json:"trailing_registry_silence_since_at,omitempty"`

	ThresholdSeconds int64  `json:"threshold_seconds"`
	ThresholdSource  string `json:"threshold_source"` // recorded | default

	// GuestQuietSeconds is the guest log's own silence, measured from its
	// last output to the window end (never from whenever this happens to
	// be read). Unknown (null, with a reason) when LogStatus isn't ok,
	// or when the window end is unknown.
	GuestQuietSeconds       *int64 `json:"guest_quiet_seconds"`
	GuestQuietUnknownReason string `json:"guest_quiet_unknown_reason,omitempty"`

	// EventsSinceGuestQuiet is a plain count of registry events at or
	// after the guest's last output -- a fact, not a verdict about whose
	// fault a stall is (the registry activity could belong to an
	// unrelated request).
	EventsSinceGuestQuiet int `json:"events_since_guest_quiet"`

	// Indication is OPTIONAL: a one-word, evidential-named summary, by a
	// fixed precedence used ONLY to pick this field -- every fact above
	// stands on its own regardless of which Indication it produced.
	Indication string `json:"indication"`
}

// defaultFetchTimeoutSeconds is this package's own fallback, not a
// recorded value: no existing status.json or Entry field names the
// install's actual fetch-timeout today (a named gap, not hidden -- see
// ThresholdSource). It matches npm's own conventional default and the
// value profrod's own install-locked-v1.mjs configures.
const defaultFetchTimeoutSeconds = 60

// nearThresholdFraction: with only a default (never recorded) threshold,
// a gap within this fraction of it either way is too close to call --
// INSUFFICIENT_EVIDENCE, not a confident over/under verdict either way.
const nearThresholdFraction = 0.2

const (
	indicationProxyShortDelivery   = "PROXY_SHORT_DELIVERY_OBSERVED"
	indicationRegistryGapOver      = "REGISTRY_GAP_OVER_THRESHOLD"
	indicationGuestQuietActive     = "GUEST_QUIET_WHILE_REGISTRY_ACTIVE"
	indicationInsufficientEvidence = "INSUFFICIENT_EVIDENCE"
	indicationNoStall              = "NO_STALL_IN_WINDOW"
)

// installStallDiagnostic is pure: every input is already read and bounded
// by progressOf's own calls; this only reports and classifies what they
// produced. windowEnd is nil exactly when progressOf couldn't establish
// this attempt's own window end (a terminal attempt with no recorded
// Ended time); windowEndUnknownReason names why, for every fact that
// depends on it. recordedFetchTimeoutSeconds is nil until some future
// status.json field actually records it; today ThresholdSource is always
// "default".
func installStallDiagnostic(attempt string, reg RegistryProgress, log ProgressLog, created time.Time, windowEnd *time.Time, windowEndUnknownReason string, now time.Time, recordedFetchTimeoutSeconds *int64) InstallStallDiagnostic {
	d := InstallStallDiagnostic{
		Contract:    "pomar.install-stall-diagnostic/v1",
		Attempt:     attempt,
		ObservedAt:  now.UTC(),
		ClockSource: "host",
	}
	switch {
	case windowEnd == nil:
		d.ElapsedUnknownReason = windowEndUnknownReason
	case created.IsZero():
		d.ElapsedUnknownReason = "attempt has no recorded Created time"
	case windowEnd.Before(created):
		d.ElapsedUnknownReason = "window end precedes Created"
	default:
		seconds := int64(windowEnd.Sub(created) / time.Second)
		d.ElapsedSeconds = &seconds
	}

	d.ThresholdSeconds, d.ThresholdSource = int64(defaultFetchTimeoutSeconds), "default"
	if recordedFetchTimeoutSeconds != nil {
		d.ThresholdSeconds, d.ThresholdSource = *recordedFetchTimeoutSeconds, "recorded"
	}

	// P2-1: per-source status, checked explicitly rather than assumed
	// from the mere absence of a flag.
	d.LogStatus, d.LogStatusReason = sourceStatusFor(log.Availability, log.ChangedDuringRead)
	d.LogWindowTruncated = log.WindowTruncated
	d.RegistryStatus, d.RegistryStatusReason = sourceStatusFor(reg.Availability, reg.ChangedDuringRead)
	if d.RegistryStatus == sourceOK && reg.Coverage == "NO_STRUCTURED_EVENTS_OBSERVED" {
		d.RegistryStatus, d.RegistryStatusReason = sourceUnknown, "the trace has bytes but no recognized pomar.npm-request/v1 events"
	}
	d.RegistryWindowTruncated = reg.WindowTruncated
	d.RegistryChangedDuringRead = reg.ChangedDuringRead

	d.EventsBeforeWindowStart = reg.EventsBeforeWindowStart
	d.EventsAfterWindowEnd = reg.EventsAfterWindowEnd
	d.EventsOutOfOrder = reg.EventsOutOfOrder

	d.SendShortCount = reg.Events["send_short"]
	d.SendShortRequests = reg.ShortRequests // already bounded/sanitized at the source (registryProgress)

	// P2-3: there is deliberately no Created -> first-retained-event
	// "start edge" gap here at all (unlike this type's first version).
	// A registry window's leading fragment can be silently dropped on a
	// partial read regardless of whether WindowTruncated ends up true for
	// THIS read, so Created can never safely stand in for "nothing
	// happened before the first event we saw." Only the registry's own
	// internal (event-to-event) gap and the end edge below are reported.
	switch {
	case reg.LongestGapSeconds != nil:
		d.LongestRegistryGapSeconds = reg.LongestGapSeconds
		d.LongestRegistryGapFromEvent, d.LongestRegistryGapFromAt = reg.LongestGapFromEvent, reg.LongestGapFromAt
		d.LongestRegistryGapToEvent, d.LongestRegistryGapToAt = reg.LongestGapToEvent, reg.LongestGapToAt
	case d.RegistryStatus != sourceOK:
		d.LongestRegistryGapUnknownReason = "registry status is " + d.RegistryStatus
	default:
		d.LongestRegistryGapUnknownReason = "fewer than two recognized, in-window events were observed"
	}

	switch {
	case windowEnd == nil:
		d.TrailingRegistrySilenceUnknownReason = windowEndUnknownReason
	case d.RegistryStatus != sourceOK:
		d.TrailingRegistrySilenceUnknownReason = "registry status is " + d.RegistryStatus
	case reg.LastEventAt == nil:
		d.TrailingRegistrySilenceUnknownReason = "no in-window registry event was observed"
	case windowEnd.Before(*reg.LastEventAt):
		d.TrailingRegistrySilenceUnknownReason = "window end precedes the last observed registry event"
	default:
		seconds := int64(windowEnd.Sub(*reg.LastEventAt) / time.Second)
		d.TrailingRegistrySilenceSeconds = &seconds
		d.TrailingRegistrySilenceSinceAt = reg.LastEventAt
	}

	// P2-4 (round two)/P2-1 (round three): GuestQuietSeconds is only ever
	// computed against the attempt's own window end -- never against
	// `now` as a stand-in when that end is unknown or inconsistent with
	// what the guest log itself reported.
	switch {
	case d.LogStatus != sourceOK:
		d.GuestQuietUnknownReason = "log status is " + d.LogStatus
	case windowEnd == nil:
		d.GuestQuietUnknownReason = windowEndUnknownReason
	case log.LastOutputAt == nil:
		d.GuestQuietUnknownReason = "no output has been observed yet"
	case windowEnd.Before(*log.LastOutputAt):
		d.GuestQuietUnknownReason = "window end precedes the guest's last observed output"
	default:
		seconds := int64(windowEnd.Sub(*log.LastOutputAt) / time.Second)
		d.GuestQuietSeconds = &seconds
	}

	d.EventsSinceGuestQuiet = reg.EventsSinceGuestQuiet

	d.Indication = indicationFor(d)
	return enforceReportCap(d)
}

func sourceStatusFor(availability string, changedDuringRead bool) (status, reason string) {
	switch availability {
	case "NOT_CREATED":
		return sourceUnavailable, "not created yet"
	case "UNAVAILABLE":
		return sourceUnavailable, "could not be read"
	}
	if changedDuringRead {
		return sourceUnknown, "the file changed during this read; the tail read may not be internally consistent"
	}
	return sourceOK, ""
}

// enforceReportCap is the last-resort guard on this report's own
// documented 4 KiB cap, measured on the actual marshaled bytes -- not
// assumed from the bounds already applied to each field. Expected to be a
// no-op given those bounds; kept as an absolute guarantee regardless.
func enforceReportCap(d InstallStallDiagnostic) InstallStallDiagnostic {
	b, err := json.Marshal(d)
	if err == nil && len(b) <= maxReportBytes {
		return d
	}
	d.SendShortRequests = nil
	d.EvidenceTruncated = true
	return d
}

func indicationFor(d InstallStallDiagnostic) string {
	anyUnknownSource := d.LogStatus != sourceOK || d.RegistryStatus != sourceOK
	anyTruncated := d.LogWindowTruncated || d.RegistryWindowTruncated
	anyUnbound := d.EventsBeforeWindowStart > 0 || d.EventsAfterWindowEnd > 0 || d.EventsOutOfOrder > 0
	nearThreshold := false
	if d.ThresholdSource == "default" {
		for _, gap := range []*int64{d.LongestRegistryGapSeconds, d.TrailingRegistrySilenceSeconds} {
			if gap == nil {
				continue
			}
			margin := float64(d.ThresholdSeconds) * nearThresholdFraction
			diff := float64(*gap - d.ThresholdSeconds)
			if diff < 0 {
				diff = -diff
			}
			if diff <= margin {
				nearThreshold = true
			}
		}
	}
	// Council P1-1: INSUFFICIENT_EVIDENCE is checked FIRST and wins
	// outright whenever any of its triggers hold -- round two's version
	// checked it last, so a truncated or unknown source sitting
	// alongside a genuine-looking gap still read as a confident
	// REGISTRY_GAP_OVER_THRESHOLD. Every fact still appears in the
	// document regardless; only the one-word summary is preempted.
	if anyUnknownSource || anyTruncated || anyUnbound || nearThreshold {
		return indicationInsufficientEvidence
	}

	registryGapOver := (d.LongestRegistryGapSeconds != nil && *d.LongestRegistryGapSeconds > d.ThresholdSeconds) ||
		(d.TrailingRegistrySilenceSeconds != nil && *d.TrailingRegistrySilenceSeconds > d.ThresholdSeconds)
	guestQuietActive := d.GuestQuietSeconds != nil && *d.GuestQuietSeconds >= d.ThresholdSeconds && d.EventsSinceGuestQuiet > 0

	switch {
	case d.SendShortCount > 0:
		return indicationProxyShortDelivery
	case registryGapOver:
		return indicationRegistryGapOver
	case guestQuietActive:
		return indicationGuestQuietActive
	default:
		return indicationNoStall
	}
}
