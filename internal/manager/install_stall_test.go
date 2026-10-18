package manager

import (
	"encoding/json"
	"testing"
	"time"
)

func seconds(n int64) *int64 { return &n }

func at(base time.Time, d time.Duration) *time.Time {
	t := base.Add(d)
	return &t
}

// council's arbitration (zc-pcc-collector-v1 amendment 1, settling the
// disagreement with pomar's review): a fixture per Indication, plus a
// two-facts-true case asserting precedence while every underlying fact
// still stands on its own regardless of which Indication it produced.
func TestInstallStallIndications(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	okLog := ProgressLog{Availability: "AVAILABLE"}
	okReg := func(extra RegistryProgress) RegistryProgress {
		extra.Availability = "AVAILABLE"
		return extra
	}

	tests := []struct {
		name  string
		reg   RegistryProgress
		log   ProgressLog
		now   time.Time
		check func(t *testing.T, d InstallStallDiagnostic)
	}{
		{
			name: "proxy short delivery observed",
			reg: okReg(RegistryProgress{Events: map[string]int{"send_short": 1}, Statuses: map[int]int{},
				ShortRequests: []ShortRequestEvidence{{Request: 7, Path: "/left-pad/-/left-pad-1.3.0.tgz", Bytes: seconds(100), Want: seconds(10000), Reason: "write failed"}},
				FirstEventAt:  at(base, time.Second), LastEventAt: at(base, 2*time.Second)}),
			log: okLog,
			now: base.Add(3 * time.Second),
			check: func(t *testing.T, d InstallStallDiagnostic) {
				if d.Indication != indicationProxyShortDelivery {
					t.Fatalf("indication = %s, want %s: %+v", d.Indication, indicationProxyShortDelivery, d)
				}
				if d.SendShortCount != 1 || len(d.SendShortRequests) != 1 || d.SendShortRequests[0].Path != "/left-pad/-/left-pad-1.3.0.tgz" {
					t.Fatalf("send-short evidence not carried through: %+v", d)
				}
			},
		},
		{
			name: "registry gap over threshold",
			reg: okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
				FirstEventAt: at(base, time.Second), LastEventAt: at(base, 3*time.Second),
				LongestGapSeconds: seconds(200), LongestGapFromEvent: "upstream_started", LongestGapFromAt: at(base, time.Second),
				LongestGapToEvent: "upstream_connected", LongestGapToAt: at(base, 201*time.Second)}),
			log: okLog,
			now: base.Add(4 * time.Second),
			check: func(t *testing.T, d InstallStallDiagnostic) {
				if d.Indication != indicationRegistryGapOver {
					t.Fatalf("indication = %s, want %s: %+v", d.Indication, indicationRegistryGapOver, d)
				}
				if d.LongestRegistryGapSeconds == nil || *d.LongestRegistryGapSeconds != 200 {
					t.Fatalf("gap not reported as a fact: %+v", d)
				}
			},
		},
		{
			name: "guest quiet while registry active",
			reg: okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
				FirstEventAt: at(base, time.Second), LastEventAt: at(base, 70*time.Second), EventsSinceGuestQuiet: 2}),
			log: ProgressLog{Availability: "AVAILABLE", LastOutputAt: at(base, 5*time.Second), QuietSeconds: seconds(70)},
			now: base.Add(75 * time.Second),
			check: func(t *testing.T, d InstallStallDiagnostic) {
				if d.Indication != indicationGuestQuietActive {
					t.Fatalf("indication = %s, want %s: %+v", d.Indication, indicationGuestQuietActive, d)
				}
				if d.EventsSinceGuestQuiet != 2 {
					t.Fatalf("event count not carried through: %+v", d)
				}
			},
		},
		{
			// Same quiet duration, but zero registry events during it:
			// GUEST_QUIET_WHILE_REGISTRY_ACTIVE requires actual activity
			// during the quiet period, not just a long quiet period.
			name: "guest quiet but registry equally silent: not guest-quiet-while-active",
			reg: okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
				// LastEventAt kept close to `now` so the trailing silence
				// (end - LastEventAt) stays small and never itself trips
				// REGISTRY_GAP_OVER_THRESHOLD, isolating EventsSinceGuestQuiet
				// as the only thing distinguishing this from the case above.
				FirstEventAt: at(base, time.Second), LastEventAt: at(base, 73*time.Second), EventsSinceGuestQuiet: 0}),
			log: ProgressLog{Availability: "AVAILABLE", LastOutputAt: at(base, 5*time.Second), QuietSeconds: seconds(70)},
			now: base.Add(75 * time.Second),
			check: func(t *testing.T, d InstallStallDiagnostic) {
				if d.Indication != indicationNoStall {
					t.Fatalf("indication = %s, want %s: zero registry activity during a quiet period must not read as guest-quiet-while-active: %+v", d.Indication, indicationNoStall, d)
				}
			},
		},
		{
			name: "insufficient evidence: registry unavailable",
			reg:  RegistryProgress{Availability: "NOT_CREATED", Events: map[string]int{}, Statuses: map[int]int{}},
			log:  okLog,
			now:  base.Add(300 * time.Second),
			check: func(t *testing.T, d InstallStallDiagnostic) {
				if d.Indication != indicationInsufficientEvidence {
					t.Fatalf("indication = %s, want %s: an unavailable source must never read as a clean NO_STALL_IN_WINDOW: %+v", d.Indication, indicationInsufficientEvidence, d)
				}
				if d.RegistryStatus != sourceUnavailable {
					t.Fatalf("registry status not reported: %+v", d)
				}
			},
		},
		{
			name: "insufficient evidence: window truncated",
			reg:  okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{}, WindowTruncated: true}),
			log:  okLog,
			now:  base.Add(300 * time.Second),
			check: func(t *testing.T, d InstallStallDiagnostic) {
				if d.Indication != indicationInsufficientEvidence {
					t.Fatalf("indication = %s, want %s: %+v", d.Indication, indicationInsufficientEvidence, d)
				}
				if !d.RegistryWindowTruncated {
					t.Fatalf("truncation not reported: %+v", d)
				}
			},
		},
		{
			name: "insufficient evidence: default threshold, gap near it",
			reg: okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
				FirstEventAt: at(base, time.Second), LastEventAt: at(base, 3*time.Second),
				LongestGapSeconds: seconds(65), LongestGapFromEvent: "a", LongestGapFromAt: at(base, time.Second),
				LongestGapToEvent: "b", LongestGapToAt: at(base, 66*time.Second)}),
			log: okLog,
			now: base.Add(4 * time.Second),
			check: func(t *testing.T, d InstallStallDiagnostic) {
				if d.Indication != indicationInsufficientEvidence {
					t.Fatalf("indication = %s, want %s: a 65s gap against an unrecorded 60s default is too close to call confidently over: %+v", d.Indication, indicationInsufficientEvidence, d)
				}
			},
		},
		{
			name: "no stall in window",
			reg: okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
				FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second)}),
			log: okLog,
			now: base.Add(3 * time.Second),
			check: func(t *testing.T, d InstallStallDiagnostic) {
				if d.Indication != indicationNoStall {
					t.Fatalf("indication = %s, want %s: %+v", d.Indication, indicationNoStall, d)
				}
			},
		},
		{
			// Two facts true at once: send_short AND a large registry gap.
			// Precedence picks PROXY_SHORT_DELIVERY_OBSERVED, but the gap
			// fact itself is still reported, unaffected by which
			// Indication won.
			name: "two facts true: precedence picks the higher one, the other fact still stands",
			reg: okReg(RegistryProgress{Events: map[string]int{"send_short": 1}, Statuses: map[int]int{},
				ShortRequests:     []ShortRequestEvidence{{Request: 1, Bytes: seconds(0), Reason: "write failed"}},
				FirstEventAt:      at(base, time.Second),
				LastEventAt:       at(base, 200*time.Second),
				LongestGapSeconds: seconds(150), LongestGapFromEvent: "received", LongestGapFromAt: at(base, 10*time.Second),
				LongestGapToEvent: "completed", LongestGapToAt: at(base, 160*time.Second)}),
			log: okLog,
			now: base.Add(205 * time.Second),
			check: func(t *testing.T, d InstallStallDiagnostic) {
				if d.Indication != indicationProxyShortDelivery {
					t.Fatalf("indication = %s, want %s (precedence)", d.Indication, indicationProxyShortDelivery)
				}
				if d.LongestRegistryGapSeconds == nil || *d.LongestRegistryGapSeconds != 150 {
					t.Fatalf("the gap fact must still be reported even though it didn't win the indication: %+v", d)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := installStallDiagnostic("att-1", tc.reg, tc.log, base, time.Time{}, false, tc.now, nil)
			if d.Contract != "pomar.install-stall-diagnostic/v1" || d.Attempt != "att-1" {
				t.Fatalf("envelope: %+v", d)
			}
			if d.ClockSource != "host" {
				t.Fatalf("clock source must always be host: %+v", d)
			}
			if d.ThresholdSource != "default" || d.ThresholdSeconds != defaultFetchTimeoutSeconds {
				t.Fatalf("threshold should default and say so when nothing is recorded: %+v", d)
			}
			tc.check(t, d)
		})
	}
}

// council amendment 2: a recorded threshold, when supplied, must be used
// and reported as such -- never silently replaced by the default.
func TestInstallStallThresholdSource(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	recorded := int64(30)
	reg := RegistryProgress{Availability: "AVAILABLE", Events: map[string]int{}, Statuses: map[int]int{},
		FirstEventAt: at(base, time.Second), LastEventAt: at(base, 50*time.Second),
		LongestGapSeconds: seconds(49), LongestGapFromEvent: "received", LongestGapFromAt: at(base, time.Second),
		LongestGapToEvent: "completed", LongestGapToAt: at(base, 50*time.Second)}
	now := base.Add(60 * time.Second)
	withDefault := installStallDiagnostic("att-2", reg, ProgressLog{Availability: "AVAILABLE"}, base, time.Time{}, false, now, nil)
	if withDefault.Indication == indicationRegistryGapOver {
		t.Fatalf("a 49s gap must not read as over the 60s default: %+v", withDefault)
	}
	withRecorded := installStallDiagnostic("att-2", reg, ProgressLog{Availability: "AVAILABLE"}, base, time.Time{}, false, now, &recorded)
	if withRecorded.ThresholdSource != "recorded" || withRecorded.ThresholdSeconds != 30 {
		t.Fatalf("recorded threshold not used: %+v", withRecorded)
	}
	if withRecorded.Indication != indicationRegistryGapOver {
		t.Fatalf("a recorded, lower threshold should change the outcome: the same 49s gap now clearly exceeds 30s: %+v", withRecorded)
	}
}

// pomar's P2-3: a truncated registry window must exclude the START edge
// (Created -> first retained event) from gap analysis -- the dropped
// leading fragment may have held continuous activity, so this interval
// was never actually observed as silent.
func TestInstallStallExcludesStartEdgeWhenTruncated(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	reg := RegistryProgress{Availability: "AVAILABLE", Events: map[string]int{}, Statuses: map[int]int{},
		WindowTruncated: true,
		FirstEventAt:    at(base, 90*time.Second), LastEventAt: at(base, 91*time.Second)}
	d := installStallDiagnostic("att-3", reg, ProgressLog{Availability: "AVAILABLE"}, base, time.Time{}, false, base.Add(92*time.Second), nil)
	if d.Indication != indicationInsufficientEvidence {
		t.Fatalf("a truncated window should itself read INSUFFICIENT_EVIDENCE: %+v", d)
	}
	// Even setting truncation aside, nothing here should manufacture a
	// 90s "observed" gap from Created to the first retained event.
	if d.LongestRegistryGapSeconds != nil && *d.LongestRegistryGapSeconds >= 90 {
		t.Fatalf("the truncated start edge must never be reported as an observed gap: %+v", d)
	}
}

// pomar's P2-4: the terminal quiet-duration freeze must itself be
// unknown, not fall back to a growing read-time value, when its own
// inputs are inconsistent.
func TestInstallStallGuestQuietUnknownOnInconsistentTerminalInputs(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	reg := RegistryProgress{Availability: "AVAILABLE", Events: map[string]int{}, Statuses: map[int]int{},
		FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second)}

	t.Run("LastOutputAt after Ended", func(t *testing.T) {
		ended := base.Add(10 * time.Second)
		lastOutput := base.Add(20 * time.Second) // after Ended: inconsistent
		readMuchLater := base.Add(10000 * time.Second)
		staleQuiet := int64(readMuchLater.Sub(lastOutput) / time.Second)
		log := ProgressLog{Availability: "AVAILABLE", LastOutputAt: &lastOutput, QuietSeconds: &staleQuiet}
		d := installStallDiagnostic("att-4", reg, log, base, ended, true, readMuchLater, nil)
		if d.GuestQuietSeconds != nil {
			t.Fatalf("an inconsistent LastOutputAt/Ended pair must report unknown, not a stale fallback value: %+v", d)
		}
		if d.GuestQuietUnknownReason == "" {
			t.Fatal("unknown guest-quiet must still say why")
		}
	})

	t.Run("terminal with no Ended", func(t *testing.T) {
		lastOutput := base.Add(5 * time.Second)
		log := ProgressLog{Availability: "AVAILABLE", LastOutputAt: &lastOutput, QuietSeconds: seconds(9999)}
		d := installStallDiagnostic("att-5", reg, log, base, time.Time{}, true, base.Add(10000*time.Second), nil)
		if d.GuestQuietSeconds != nil {
			t.Fatalf("a terminal attempt with no Ended must report unknown: %+v", d)
		}
	})

	t.Run("consistent terminal inputs still freeze correctly", func(t *testing.T) {
		ended := base.Add(50 * time.Second)
		lastOutput := base.Add(5 * time.Second)
		readMuchLater := base.Add(10000 * time.Second)
		staleQuiet := int64(readMuchLater.Sub(lastOutput) / time.Second)
		log := ProgressLog{Availability: "AVAILABLE", LastOutputAt: &lastOutput, QuietSeconds: &staleQuiet}
		d := installStallDiagnostic("att-6", reg, log, base, ended, true, readMuchLater, nil)
		if d.GuestQuietSeconds == nil || *d.GuestQuietSeconds != 45 {
			t.Fatalf("a consistent terminal pair should freeze at Ended-LastOutputAt (45s), not the stale %ds: %+v", staleQuiet, d)
		}
	})
}

// pomar's P2-1: an unavailable or unknown source must never silently read
// as a clean "nothing happened" observation.
func TestInstallStallPerSourceStatus(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	reg := RegistryProgress{Availability: "AVAILABLE", Events: map[string]int{}, Statuses: map[int]int{},
		FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second)}

	t.Run("log not created", func(t *testing.T) {
		d := installStallDiagnostic("att-7", reg, ProgressLog{Availability: "NOT_CREATED"}, base, time.Time{}, false, base.Add(3*time.Second), nil)
		if d.LogStatus != sourceUnavailable {
			t.Fatalf("LogStatus = %s, want unavailable: %+v", d.LogStatus, d)
		}
		if d.Indication != indicationInsufficientEvidence {
			t.Fatalf("indication = %s, want insufficient evidence: %+v", d.Indication, d)
		}
	})
	t.Run("log changed during read", func(t *testing.T) {
		d := installStallDiagnostic("att-8", reg, ProgressLog{Availability: "AVAILABLE", ChangedDuringRead: true}, base, time.Time{}, false, base.Add(3*time.Second), nil)
		if d.LogStatus != sourceUnknown {
			t.Fatalf("LogStatus = %s, want unknown (a non-atomic read mid-write): %+v", d.LogStatus, d)
		}
	})
	t.Run("registry has bytes but no recognized events", func(t *testing.T) {
		noisy := RegistryProgress{Availability: "AVAILABLE", Coverage: "NO_STRUCTURED_EVENTS_OBSERVED", Events: map[string]int{}, Statuses: map[int]int{}}
		d := installStallDiagnostic("att-9", noisy, ProgressLog{Availability: "AVAILABLE"}, base, time.Time{}, false, base.Add(3*time.Second), nil)
		if d.RegistryStatus != sourceUnknown {
			t.Fatalf("RegistryStatus = %s, want unknown: %+v", d.RegistryStatus, d)
		}
	})
}

// pomar's P2-2: each evidence entry's own Path/Reason must be explicitly
// bounded here, not trusted to upstream redaction alone.
func TestInstallStallBoundsEvidenceFields(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	longPath := make([]byte, 3501)
	for i := range longPath {
		longPath[i] = 'a'
	}
	reg := RegistryProgress{Availability: "AVAILABLE", Events: map[string]int{"send_short": 1}, Statuses: map[int]int{},
		ShortRequests: []ShortRequestEvidence{{Request: 1, Path: string(longPath), Reason: "write failed", Bytes: seconds(0)}},
		FirstEventAt:  at(base, time.Second), LastEventAt: at(base, 2*time.Second)}
	d := installStallDiagnostic("att-10", reg, ProgressLog{Availability: "AVAILABLE"}, base, time.Time{}, false, base.Add(3*time.Second), nil)
	if len(d.SendShortRequests) != 1 {
		t.Fatalf("evidence dropped entirely, not just bounded: %+v", d)
	}
	if len(d.SendShortRequests[0].Path) > maxEvidencePathLen+20 {
		t.Fatalf("a 3501-byte path must be bounded, not passed through: got %d bytes", len(d.SendShortRequests[0].Path))
	}
}

// council amendment 6 / pomar's P2-2 counterexample: the report must
// actually fit its own documented 4 KiB cap under worst-case population,
// including pomar's exact 3-entries-of-3650-bytes-each construction.
func TestInstallStallFitsItsDocumentedCap(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	longPath := make([]byte, 3501)
	for i := range longPath {
		longPath[i] = 'a'
	}
	var evidence []ShortRequestEvidence
	for i := uint64(1); i <= maxShortRequestEvidence; i++ {
		evidence = append(evidence, ShortRequestEvidence{
			Request: i, Path: string(longPath), Bytes: seconds(9999999999), Want: seconds(9999999999), Reason: "connection reset",
		})
	}
	reg := RegistryProgress{Availability: "AVAILABLE", Events: map[string]int{"send_short": maxShortRequestEvidence}, Statuses: map[int]int{},
		ShortRequests:     evidence,
		FirstEventAt:      at(base, time.Second),
		LastEventAt:       at(base, 2*time.Second),
		LongestGapSeconds: seconds(9999999999), LongestGapFromEvent: "upstream_connect_started", LongestGapFromAt: at(base, time.Second),
		LongestGapToEvent: "upstream_connected", LongestGapToAt: at(base, 2*time.Second)}
	log := ProgressLog{Availability: "AVAILABLE", LastOutputAt: at(base, time.Second), QuietSeconds: seconds(9999999999)}
	d := installStallDiagnostic("a-worst-case-attempt-id-of-realistic-maximum-length-0123456789", reg, log, base, base.Add(3*time.Second), true, base.Add(4*time.Second), seconds(30))

	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	const capBytes = 4 << 10
	if len(b) > capBytes {
		t.Fatalf("worst-case InstallStallDiagnostic is %d bytes, over the documented %d-byte cap", len(b), capBytes)
	}
}
