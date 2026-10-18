package manager

import "time"

// Source status: whether a given evidence source (the guest log, the
// registry trace) was actually readable and parseable for this read.
const (
	sourceOK          = "ok"
	sourceUnknown     = "unknown"
	sourceUnavailable = "unavailable"
)

// maxEvidencePathLen bounds each ShortRequestEvidence's Path field as
// reported here (pomar's review: npmproxy's own Path is the request's
// URL path, with no length bound of its own beyond the log line's 4096-byte
// cap -- a handful of such paths alone can blow well past this report's
// own 4 KiB cap long before the line-level bound would ever stop them).
const maxEvidencePathLen = 200

// maxEvidenceReasonLen similarly bounds Reason, though shortReason's own
// classifier already keeps it to a handful of fixed words -- bounded here
// too, defensively, rather than trusted by assumption.
const maxEvidenceReasonLen = 64

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
// from evidence that can't actually support that certainty -- a gap
// between unrelated concurrent requests isn't one fetch timeout, and
// registry activity during a guest-quiet period doesn't rule out the
// proxy. Every measured value below is reported as a fact plus its own
// source status, with an OPTIONAL, separately-precedenced Indication
// using evidential (not causal) names, and INSUFFICIENT_EVIDENCE winning
// outright whenever any source is less than fully known.
//
// pomar's four independent source findings, also folded in:
//   - P2-1: per-source status (ok/unknown/unavailable) is now explicit
//     and checked, so UNAVAILABLE-plus-no-events can never read as a
//     clean NO_STALL_IN_WINDOW; log.ChangedDuringRead now also counts as
//     LogStatus "unknown" (a non-atomic read mid-write), not silently
//     discarded.
//   - P2-2: each evidence entry's Path/Reason are explicitly bounded
//     (maxEvidencePathLen/maxEvidenceReasonLen) with an overflow flag,
//     rather than trusting upstream redaction to also be a size bound.
//   - P2-3: the registry window's own truncation excludes the START edge
//     (Created -> first retained event) from gap analysis entirely -- a
//     dropped leading fragment may have held continuous activity, so
//     that interval is excluded as unknown, never reported as an
//     observed silence.
//   - P2-4: the terminal-attempt quiet-duration freeze (this package's
//     prior fix) is itself marked unknown, not silently falling back to
//     a growing read-time value, when its own inputs are inconsistent
//     (LastOutputAt after Ended, or Ended missing on a terminal attempt).
type InstallStallDiagnostic struct {
	Contract    string    `json:"contract"`
	Attempt     string    `json:"attempt"`
	ObservedAt  time.Time `json:"observed_at"`
	ClockSource string    `json:"clock_source"` // always "host"

	ElapsedSeconds *int64 `json:"elapsed_seconds,omitempty"`

	LogStatus          string `json:"log_status"` // ok | unknown | unavailable
	LogStatusReason    string `json:"log_status_reason,omitempty"`
	LogWindowTruncated bool   `json:"log_window_truncated"`

	RegistryStatus          string `json:"registry_status"` // ok | unknown | unavailable
	RegistryStatusReason    string `json:"registry_status_reason,omitempty"`
	RegistryWindowTruncated bool   `json:"registry_window_truncated"`

	SendShortCount    int                    `json:"send_short_count"`
	SendShortRequests []ShortRequestEvidence `json:"send_short_requests,omitempty"`

	// The registry window's own single largest gap between two
	// consecutive recognized events (never the start edge, which is
	// excluded entirely when the window is truncated -- P2-3 -- and
	// never the end edge, which is a separate, explicitly-named fact
	// below, not folded into this one to avoid conflating "an internal
	// gap we actually observed" with "silence since the last thing we
	// saw, of unknown duration going forward").
	LongestRegistryGapSeconds   *int64     `json:"longest_registry_gap_seconds,omitempty"`
	LongestRegistryGapFromEvent string     `json:"longest_registry_gap_from_event,omitempty"`
	LongestRegistryGapFromAt    *time.Time `json:"longest_registry_gap_from_at,omitempty"`
	LongestRegistryGapToEvent   string     `json:"longest_registry_gap_to_event,omitempty"`
	LongestRegistryGapToAt      *time.Time `json:"longest_registry_gap_to_at,omitempty"`

	// The end edge: the last recognized registry event to Ended
	// (terminal) or ObservedAt (still running). Named separately from
	// the internal gap above.
	TrailingRegistrySilenceSeconds *int64     `json:"trailing_registry_silence_seconds,omitempty"`
	TrailingRegistrySilenceSinceAt *time.Time `json:"trailing_registry_silence_since_at,omitempty"`

	ThresholdSeconds int64  `json:"threshold_seconds"`
	ThresholdSource  string `json:"threshold_source"` // recorded | default

	// GuestQuietSeconds is the guest log's own silence, measured from its
	// last output to Ended (terminal) or ObservedAt (still running) --
	// never from whenever this happens to be read. Unknown (nil, with a
	// reason) when LogStatus isn't ok, or when the terminal freeze's own
	// inputs are inconsistent (P2-4).
	GuestQuietSeconds       *int64 `json:"guest_quiet_seconds,omitempty"`
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
// produced. recordedFetchTimeoutSeconds is nil until some future
// status.json field actually records it; today ThresholdSource is always
// "default".
func installStallDiagnostic(attempt string, reg RegistryProgress, log ProgressLog, created, ended time.Time, terminal bool, now time.Time, recordedFetchTimeoutSeconds *int64) InstallStallDiagnostic {
	d := InstallStallDiagnostic{
		Contract:    "pomar.install-stall-diagnostic/v1",
		Attempt:     attempt,
		ObservedAt:  now.UTC(),
		ClockSource: "host",
	}
	end := now
	if terminal && !ended.IsZero() {
		end = ended
	}
	if !created.IsZero() && !end.Before(created) {
		seconds := int64(end.Sub(created) / time.Second)
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
	d.RegistryStatus, d.RegistryStatusReason = sourceStatusFor(reg.Availability, false)
	if d.RegistryStatus == sourceOK && reg.Coverage == "NO_STRUCTURED_EVENTS_OBSERVED" {
		d.RegistryStatus, d.RegistryStatusReason = sourceUnknown, "the trace has bytes but no recognized pomar.npm-request/v1 events"
	}
	d.RegistryWindowTruncated = reg.WindowTruncated

	d.SendShortCount = reg.Events["send_short"]
	d.SendShortRequests = boundedEvidence(reg.ShortRequests)

	// P2-3: there is deliberately no Created -> first-retained-event
	// "start edge" gap here at all (unlike this type's first version).
	// A registry window's leading fragment can be silently dropped on a
	// partial read regardless of whether WindowTruncated ends up true for
	// THIS read, so Created can never safely stand in for "nothing
	// happened before the first event we saw." Only the registry's own
	// internal (event-to-event) gap and the end edge below are reported.
	if reg.LongestGapSeconds != nil {
		d.LongestRegistryGapSeconds = reg.LongestGapSeconds
		d.LongestRegistryGapFromEvent, d.LongestRegistryGapFromAt = reg.LongestGapFromEvent, reg.LongestGapFromAt
		d.LongestRegistryGapToEvent, d.LongestRegistryGapToAt = reg.LongestGapToEvent, reg.LongestGapToAt
	}

	if reg.LastEventAt != nil && !end.Before(*reg.LastEventAt) {
		seconds := int64(end.Sub(*reg.LastEventAt) / time.Second)
		d.TrailingRegistrySilenceSeconds = &seconds
		d.TrailingRegistrySilenceSinceAt = reg.LastEventAt
	}

	// P2-4: the terminal freeze is itself only valid when its own inputs
	// are consistent; otherwise this is unknown, not a fallback to a
	// read-time value that would keep growing with wall-clock time.
	switch {
	case d.LogStatus != sourceOK:
		d.GuestQuietUnknownReason = "log status is " + d.LogStatus
	case terminal && (ended.IsZero() || log.LastOutputAt == nil || ended.Before(*log.LastOutputAt)):
		d.GuestQuietUnknownReason = "terminal attempt has no consistent Ended/LastOutputAt pair to measure from"
	case !terminal && log.QuietSeconds != nil:
		d.GuestQuietSeconds = log.QuietSeconds
	case terminal:
		frozen := int64(ended.Sub(*log.LastOutputAt) / time.Second)
		d.GuestQuietSeconds = &frozen
	default:
		d.GuestQuietUnknownReason = "no output has been observed yet"
	}

	d.EventsSinceGuestQuiet = reg.EventsSinceGuestQuiet

	d.Indication = indicationFor(d)
	return d
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

// boundedEvidence bounds each entry's own Path/Reason (P2-2): npmproxy's
// Path is a request's URL path with no length bound of its own short of
// the log line's 4096-byte cap, and even 3 such entries can blow well
// past this report's own 4 KiB cap long before that line-level bound ever
// would.
func boundedEvidence(in []ShortRequestEvidence) []ShortRequestEvidence {
	if in == nil {
		return nil
	}
	out := make([]ShortRequestEvidence, len(in))
	for i, e := range in {
		out[i] = e
		if len(out[i].Path) > maxEvidencePathLen {
			out[i].Path = out[i].Path[:maxEvidencePathLen] + "...(truncated)"
		}
		if len(out[i].Reason) > maxEvidenceReasonLen {
			out[i].Reason = out[i].Reason[:maxEvidenceReasonLen] + "...(truncated)"
		}
	}
	return out
}

func indicationFor(d InstallStallDiagnostic) string {
	anyUnknownSource := d.LogStatus != sourceOK || d.RegistryStatus != sourceOK
	anyTruncated := d.LogWindowTruncated || d.RegistryWindowTruncated
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
	insufficientEvidence := anyUnknownSource || anyTruncated || nearThreshold

	// A gap "near" an unrecorded (default) threshold can't confidently be
	// called over it either -- nearThreshold itself disqualifies
	// registryGapOver, so that ambiguous zone falls through to
	// INSUFFICIENT_EVIDENCE rather than a false-confident verdict.
	registryGapOver := !nearThreshold && ((d.LongestRegistryGapSeconds != nil && *d.LongestRegistryGapSeconds > d.ThresholdSeconds) ||
		(d.TrailingRegistrySilenceSeconds != nil && *d.TrailingRegistrySilenceSeconds > d.ThresholdSeconds))
	guestQuietActive := d.GuestQuietSeconds != nil && *d.GuestQuietSeconds >= d.ThresholdSeconds && d.EventsSinceGuestQuiet > 0

	switch {
	case d.SendShortCount > 0:
		return indicationProxyShortDelivery
	case registryGapOver:
		return indicationRegistryGapOver
	case guestQuietActive:
		return indicationGuestQuietActive
	case insufficientEvidence:
		return indicationInsufficientEvidence
	default:
		return indicationNoStall
	}
}
