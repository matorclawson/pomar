package manager

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/npmproxy"
)

func seconds(n int64) *int64 { return &n }

func at(base time.Time, d time.Duration) *time.Time {
	t := base.Add(d)
	return &t
}

// end returns a windowEnd pointer, the common case for these tests.
func end(base time.Time, d time.Duration) *time.Time {
	t := base.Add(d)
	return &t
}

// council's round-three review (zc-pomar141-073f-v1), blocking P1-1:
// INSUFFICIENT_EVIDENCE must be checked FIRST and win outright whenever
// any of its own triggers hold, even alongside a fact that would
// otherwise read as a confident evidential Indication -- round two had it
// last, so a truncated/unknown source next to a genuine-looking gap
// still read as REGISTRY_GAP_OVER_THRESHOLD.
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
		end   *time.Time
		check func(t *testing.T, d InstallStallDiagnostic)
	}{
		{
			name: "proxy short delivery observed",
			reg: okReg(RegistryProgress{Events: map[string]int{"send_short": 1}, Statuses: map[int]int{},
				ShortRequests: []ShortRequestEvidence{{Request: 7, Path: "/left-pad/-/left-pad-1.3.0.tgz", Bytes: seconds(100), Want: seconds(10000), Reason: "write failed"}},
				FirstEventAt:  at(base, time.Second), LastEventAt: at(base, 2*time.Second)}),
			log: okLog,
			end: end(base, 3*time.Second),
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
			end: end(base, 4*time.Second),
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
			log: ProgressLog{Availability: "AVAILABLE", LastOutputAt: at(base, 5*time.Second)},
			end: end(base, 75*time.Second),
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
			// Same quiet duration, but zero registry events during it.
			name: "guest quiet but registry equally silent: not guest-quiet-while-active",
			reg: okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
				FirstEventAt: at(base, time.Second), LastEventAt: at(base, 73*time.Second), EventsSinceGuestQuiet: 0}),
			log: ProgressLog{Availability: "AVAILABLE", LastOutputAt: at(base, 5*time.Second)},
			end: end(base, 75*time.Second),
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
			end:  end(base, 300*time.Second),
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
			end:  end(base, 300*time.Second),
			check: func(t *testing.T, d InstallStallDiagnostic) {
				if d.Indication != indicationInsufficientEvidence {
					t.Fatalf("indication = %s, want %s: %+v", d.Indication, indicationInsufficientEvidence, d)
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
			end: end(base, 4*time.Second),
			check: func(t *testing.T, d InstallStallDiagnostic) {
				if d.Indication != indicationInsufficientEvidence {
					t.Fatalf("indication = %s, want %s: a 65s gap against an unrecorded 60s default is too close to call confidently over: %+v", d.Indication, indicationInsufficientEvidence, d)
				}
			},
		},
		{
			// council P1-1's exact scenario: a genuine send_short fact
			// AND a truncated/unknown source at the same time. The
			// facts (SendShortCount) still appear, but the Indication
			// must be INSUFFICIENT_EVIDENCE, not the evidential class.
			name: "insufficient evidence wins over a genuine fact, which still appears",
			reg: okReg(RegistryProgress{Events: map[string]int{"send_short": 1}, Statuses: map[int]int{},
				ShortRequests: []ShortRequestEvidence{{Request: 1, Bytes: seconds(0), Reason: "write failed"}},
				FirstEventAt:  at(base, time.Second), LastEventAt: at(base, 2*time.Second), WindowTruncated: true}),
			log: okLog,
			end: end(base, 3*time.Second),
			check: func(t *testing.T, d InstallStallDiagnostic) {
				if d.Indication != indicationInsufficientEvidence {
					t.Fatalf("indication = %s, want %s: a truncated source must preempt even a genuine send_short fact: %+v", d.Indication, indicationInsufficientEvidence, d)
				}
				if d.SendShortCount != 1 {
					t.Fatalf("the send_short fact must still be reported even though it didn't win the indication: %+v", d)
				}
			},
		},
		{
			name: "no stall in window",
			reg: okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
				FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second)}),
			log: okLog,
			end: end(base, 3*time.Second),
			check: func(t *testing.T, d InstallStallDiagnostic) {
				if d.Indication != indicationNoStall {
					t.Fatalf("indication = %s, want %s: %+v", d.Indication, indicationNoStall, d)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := installStallDiagnostic("att-1", tc.reg, tc.log, base, tc.end, "", *tc.end, nil)
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
	we := end(base, 60*time.Second)
	withDefault := installStallDiagnostic("att-2", reg, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, nil)
	if withDefault.Indication == indicationRegistryGapOver {
		t.Fatalf("a 49s gap must not read as over the 60s default: %+v", withDefault)
	}
	withRecorded := installStallDiagnostic("att-2", reg, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, &recorded)
	if withRecorded.ThresholdSource != "recorded" || withRecorded.ThresholdSeconds != 30 {
		t.Fatalf("recorded threshold not used: %+v", withRecorded)
	}
	if withRecorded.Indication != indicationRegistryGapOver {
		t.Fatalf("a recorded, lower threshold should change the outcome: the same 49s gap now clearly exceeds 30s: %+v", withRecorded)
	}
}

// pomar's P2-3: a truncated registry window must exclude the START edge
// (Created -> first retained event) from gap analysis entirely.
func TestInstallStallExcludesStartEdgeWhenTruncated(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	reg := RegistryProgress{Availability: "AVAILABLE", Events: map[string]int{}, Statuses: map[int]int{},
		WindowTruncated: true,
		FirstEventAt:    at(base, 90*time.Second), LastEventAt: at(base, 91*time.Second)}
	we := end(base, 92*time.Second)
	d := installStallDiagnostic("att-3", reg, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, nil)
	if d.Indication != indicationInsufficientEvidence {
		t.Fatalf("a truncated window should itself read INSUFFICIENT_EVIDENCE: %+v", d)
	}
	if d.LongestRegistryGapSeconds != nil && *d.LongestRegistryGapSeconds >= 90 {
		t.Fatalf("the truncated start edge must never be reported as an observed gap: %+v", d)
	}
}

// council P2-1 (round three): the trailing silence, GuestQuietSeconds and
// ElapsedSeconds must all report unknown -- never fall back to `now` --
// when the attempt's own window end is unknown (terminal, no Ended).
func TestInstallStallFactsUnknownWhenWindowEndUnknown(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	reg := RegistryProgress{Availability: "AVAILABLE", Events: map[string]int{}, Statuses: map[int]int{},
		FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second)}
	log := ProgressLog{Availability: "AVAILABLE", LastOutputAt: at(base, 2*time.Second)}
	readMuchLater := base.Add(10000 * time.Second)
	d := installStallDiagnostic("att-4", reg, log, base, nil, "attempt is terminal but recorded no Ended time", readMuchLater, nil)
	if d.ElapsedSeconds != nil || d.ElapsedUnknownReason == "" {
		t.Fatalf("ElapsedSeconds must be unknown, not computed against now: %+v", d)
	}
	if d.TrailingRegistrySilenceSeconds != nil || d.TrailingRegistrySilenceUnknownReason == "" {
		t.Fatalf("TrailingRegistrySilenceSeconds must be unknown, not computed against now: %+v", d)
	}
	if d.GuestQuietSeconds != nil || d.GuestQuietUnknownReason == "" {
		t.Fatalf("GuestQuietSeconds must be unknown, not computed against now: %+v", d)
	}
	// council N2: a nil windowEnd must itself bar NO_STALL_IN_WINDOW --
	// not knowing where the window even ends is not the same as having
	// observed its full extent and found nothing.
	if !d.AttemptIntervalUnknown || d.AttemptIntervalUnknownReason == "" {
		t.Fatalf("AttemptIntervalUnknown must be set, with its reason: %+v", d)
	}
	if d.Indication != indicationInsufficientEvidence {
		t.Fatalf("indication = %s, want %s: a nil windowEnd must never read as a confident NO_STALL_IN_WINDOW: %+v", d.Indication, indicationInsufficientEvidence, d)
	}
}

// council P2-2: events outside [Created, windowEnd] or out of order must
// be reported as their own facts and excluded from gap analysis.
func TestInstallStallReportsUnboundEvents(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	reg := RegistryProgress{Availability: "AVAILABLE", Events: map[string]int{}, Statuses: map[int]int{},
		EventsBeforeWindowStart: 1, EventsAfterWindowEnd: 2, EventsOutOfOrder: 3}
	we := end(base, 10*time.Second)
	d := installStallDiagnostic("att-5", reg, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, nil)
	if d.EventsBeforeWindowStart != 1 || d.EventsAfterWindowEnd != 2 || d.EventsOutOfOrder != 3 {
		t.Fatalf("unbound event counts not carried through: %+v", d)
	}
	if d.Indication != indicationInsufficientEvidence {
		t.Fatalf("a non-zero unbound-event count must itself trigger INSUFFICIENT_EVIDENCE: %+v", d)
	}
}

// pomar's P2-1: an unavailable or unknown source must never silently read
// as a clean "nothing happened" observation.
func TestInstallStallPerSourceStatus(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	reg := RegistryProgress{Availability: "AVAILABLE", Events: map[string]int{}, Statuses: map[int]int{},
		FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second)}
	we := end(base, 3*time.Second)

	t.Run("log not created", func(t *testing.T) {
		d := installStallDiagnostic("att-7", reg, ProgressLog{Availability: "NOT_CREATED"}, base, we, "", *we, nil)
		if d.LogStatus != sourceUnavailable {
			t.Fatalf("LogStatus = %s, want unavailable: %+v", d.LogStatus, d)
		}
		if d.Indication != indicationInsufficientEvidence {
			t.Fatalf("indication = %s, want insufficient evidence: %+v", d.Indication, d)
		}
	})
	t.Run("log changed during read", func(t *testing.T) {
		d := installStallDiagnostic("att-8", reg, ProgressLog{Availability: "AVAILABLE", ChangedDuringRead: true}, base, we, "", *we, nil)
		if d.LogStatus != sourceUnknown {
			t.Fatalf("LogStatus = %s, want unknown (a non-atomic read mid-write): %+v", d.LogStatus, d)
		}
	})
	t.Run("registry has bytes but no recognized events", func(t *testing.T) {
		noisy := RegistryProgress{Availability: "AVAILABLE", Coverage: "NO_STRUCTURED_EVENTS_OBSERVED", Events: map[string]int{}, Statuses: map[int]int{}}
		d := installStallDiagnostic("att-9", noisy, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, nil)
		if d.RegistryStatus != sourceUnknown {
			t.Fatalf("RegistryStatus = %s, want unknown: %+v", d.RegistryStatus, d)
		}
	})
	t.Run("registry changed during read", func(t *testing.T) {
		changed := RegistryProgress{Availability: "AVAILABLE", ChangedDuringRead: true, Events: map[string]int{}, Statuses: map[int]int{}}
		d := installStallDiagnostic("att-10", changed, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, nil)
		if d.RegistryStatus != sourceUnknown {
			t.Fatalf("RegistryStatus = %s, want unknown: %+v", d.RegistryStatus, d)
		}
		if !d.RegistryChangedDuringRead {
			t.Fatalf("RegistryChangedDuringRead not carried through: %+v", d)
		}
	})
}

// council amendment 6 / pomar's P2-2 counterexample: the report must
// actually fit its own documented 4 KiB cap under worst-case population.
// registryProgress's own evidence bounding (closedEvidence) should make
// this unreachable in practice; this still exercises the last-resort
// enforceReportCap guard directly, bypassing that bounding, to prove the
// guard itself works.
func TestInstallStallEnforcesCapAsALastResort(t *testing.T) {
	huge := make([]ShortRequestEvidence, 0, 50)
	for i := 0; i < 50; i++ {
		huge = append(huge, ShortRequestEvidence{Request: uint64(i), Path: "/left-pad/-/left-pad-1.3.0.tgz", Reason: "write failed", Bytes: seconds(123456789), Want: seconds(987654321)})
	}
	d := InstallStallDiagnostic{Contract: "pomar.install-stall-diagnostic/v1", SendShortRequests: huge}
	// Not a realistic construction (registryProgress itself bounds to 3
	// entries before this ever runs) -- isolates enforceReportCap's own
	// behavior given an oversized input, regardless of how it got there.
	capped := enforceReportCap(d)
	b, err := json.Marshal(capped)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > maxReportBytes {
		t.Fatalf("enforceReportCap let %d bytes through, over the %d cap", len(b), maxReportBytes)
	}
	if !capped.EvidenceTruncated {
		t.Fatal("EvidenceTruncated must be set when evidence was dropped to meet the cap")
	}
}

// council amendment 6: a worst-case REAL construction (maximal bounded
// evidence from registryProgress's own closedEvidence, not bypassing it)
// must also fit, without ever needing the last-resort guard.
func TestInstallStallRealisticWorstCaseFitsWithoutTruncation(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	longPath := make([]byte, 3501)
	for i := range longPath {
		longPath[i] = 'a'
	}
	var evidence []ShortRequestEvidence
	for i := uint64(1); i <= maxShortRequestEvidence; i++ {
		evidence = append(evidence, closedEvidence(ShortRequestEvidence{
			Request: i, Path: string(longPath), Bytes: seconds(9999999999), Want: seconds(9999999999), Reason: "connection reset",
		}))
	}
	reg := RegistryProgress{Availability: "AVAILABLE", Events: map[string]int{"send_short": maxShortRequestEvidence}, Statuses: map[int]int{},
		ShortRequests:     evidence,
		FirstEventAt:      at(base, time.Second),
		LastEventAt:       at(base, 2*time.Second),
		LongestGapSeconds: seconds(9999999999), LongestGapFromEvent: "upstream_connect_started", LongestGapFromAt: at(base, time.Second),
		LongestGapToEvent: "upstream_connected", LongestGapToAt: at(base, 2*time.Second)}
	log := ProgressLog{Availability: "AVAILABLE", LastOutputAt: at(base, time.Second)}
	we := end(base, 4*time.Second)
	attempt := "a-worst-case-attempt-id-of-realistic-maximum-length-0123456789"
	d := installStallDiagnostic(attempt, reg, log, base, we, "", *we, seconds(30))

	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > maxReportBytes {
		t.Fatalf("worst-case InstallStallDiagnostic is %d bytes, over the documented %d-byte cap", len(b), maxReportBytes)
	}
	if d.EvidenceTruncated {
		t.Fatalf("the per-entry bounds (closedEvidence) should already keep this under the cap, without needing to drop the whole evidence array: %+v", d)
	}
	if len(d.SendShortRequests) != maxShortRequestEvidence {
		t.Fatalf("evidence dropped entirely: %+v", d)
	}
	for _, e := range d.SendShortRequests {
		if len(e.Path) > maxEvidencePathLen {
			t.Fatalf("a path must be bounded: got %d bytes", len(e.Path))
		}
	}
}

// Confirms installStallDiagnostic itself actually calls the cap guard
// (not just that enforceReportCap works in isolation): a RegistryProgress
// carrying far more evidence than registryProgress's own append-bound
// would ever produce (a caller can still construct one directly, as this
// test does) must still come out under the cap once run through the real
// function, not just when enforceReportCap is called by hand.
func TestInstallStallDiagnosticActuallyEnforcesTheCap(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	var huge []ShortRequestEvidence
	for i := 0; i < 50; i++ {
		huge = append(huge, ShortRequestEvidence{Request: uint64(i), Path: "/left-pad/-/left-pad-1.3.0.tgz", Reason: "write failed", Bytes: seconds(123456789), Want: seconds(987654321)})
	}
	reg := RegistryProgress{Availability: "AVAILABLE", Events: map[string]int{"send_short": 50}, Statuses: map[int]int{}, ShortRequests: huge}
	we := end(base, time.Second)
	d := installStallDiagnostic("att-cap", reg, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, nil)
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > maxReportBytes {
		t.Fatalf("installStallDiagnostic let %d bytes through, over the %d cap -- enforceReportCap isn't actually wired in", len(b), maxReportBytes)
	}
}

// council P2-3: an integration-level test through the real progressOf
// wiring (a real attempt directory, a real npmproxy Handler write, real
// Entry.Created/Ended), not just the pure installStallDiagnostic function
// in isolation -- several mutants (the progressOf wiring, UNAVAILABLE
// read as ok, log truncation) only show up end to end.
func TestProgressOfWiresInstallStallEndToEnd(t *testing.T) {
	m, _, v := openSigning(t, false)
	id := "install-stall-e2e"
	rec := filepath.Join(v.Root(), attemptsDir, id)
	if err := os.MkdirAll(rec, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rec, logName), []byte("installing\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cacheDir := t.TempDir()
	sum := strings.Repeat("c", 128)
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
	w := &failAfterWriter{allow: 50}
	p.Handler(file).ServeHTTP(w, httptest.NewRequest("GET", "/pkg/-/pkg-1.tgz", nil))

	// council C4 (M05L/M05q/M05C): Created and the `now` passed to
	// progressOf are both computed from ONE time.Now() call, taken AFTER
	// the real npmproxy Handler above has already stamped its own events
	// with the real wall clock (so none of them read as EventsInFuture),
	// giving an EXACT expected ElapsedSeconds -- the prior +/-5s tolerance
	// (from two separate, independently-drifting time.Now() calls) could
	// not tell "the real e.Created was wired through" apart from "some
	// other, nearby, wrong time was".
	fixedNow := time.Now()
	created := fixedNow.Add(-30 * time.Second)
	e := Entry{Attempt: id, State: StateRunning, Created: created}
	obs := m.progressOf(e, fixedNow)
	if obs.InstallStall.Contract != "pomar.install-stall-diagnostic/v1" || obs.InstallStall.Attempt != id {
		t.Fatalf("envelope not wired: %+v", obs.InstallStall)
	}
	if obs.InstallStall.Indication != indicationProxyShortDelivery {
		t.Fatalf("a real send_short, through the real pipeline, should produce %s: %+v", indicationProxyShortDelivery, obs.InstallStall)
	}
	if obs.InstallStall.SendShortCount != 1 || len(obs.InstallStall.SendShortRequests) != 1 {
		t.Fatalf("real evidence not wired through: %+v", obs.InstallStall)
	}
	if obs.InstallStall.RegistryStatus != sourceOK {
		t.Fatalf("a real, successfully-read registry trace must read ok, not %s: %+v", obs.InstallStall.RegistryStatus, obs.InstallStall)
	}
	// Council M05b (round 6 mutation re-run at 0c2f536): nothing here
	// previously pinned that progressOf's own call site actually passes
	// THIS attempt's real p.Log and e.Created through, as opposed to some
	// other/zero value -- a mutant swapping an argument, or passing a
	// fresh zero-value ProgressLog/time.Time instead of the real ones,
	// would still have passed every assertion above.
	if obs.InstallStall.LogStatus != sourceOK {
		t.Fatalf("the real log written for this attempt must flow through as LogStatus ok, not %s -- the wiring must pass THIS attempt's own p.Log, not a substitute: %+v", obs.InstallStall.LogStatus, obs.InstallStall)
	}
	if obs.InstallStall.ElapsedSeconds == nil || *obs.InstallStall.ElapsedSeconds != 30 {
		t.Fatalf("ElapsedSeconds must be exactly 30 (fixedNow - 30s == created, both from one time.Now() call): %+v", obs.InstallStall)
	}

	// Now with no npmproxy.log at all: RegistryStatus must read
	// unavailable, never silently "ok" -- the exact UNAVAILABLE-as-ok
	// mutant category council named.
	id2 := "install-stall-e2e-no-registry"
	rec2 := filepath.Join(v.Root(), attemptsDir, id2)
	if err := os.MkdirAll(rec2, 0700); err != nil {
		t.Fatal(err)
	}
	e2 := Entry{Attempt: id2, State: StateRunning, Created: created}
	obs2 := m.progressOf(e2, time.Now())
	if obs2.InstallStall.RegistryStatus != sourceUnavailable {
		t.Fatalf("a never-created registry trace must read unavailable: %+v", obs2.InstallStall)
	}
	if obs2.InstallStall.Indication != indicationInsufficientEvidence {
		t.Fatalf("an unavailable source must never read as a clean indication: %+v", obs2.InstallStall)
	}

	// A terminal attempt with no recorded Ended time: every window-end
	// dependent fact must report unknown, not fall back to now.
	id3 := "install-stall-e2e-terminal-no-ended"
	rec3 := filepath.Join(v.Root(), attemptsDir, id3)
	if err := os.MkdirAll(rec3, 0700); err != nil {
		t.Fatal(err)
	}
	e3 := Entry{Attempt: id3, State: StateExited, Created: created} // terminal, Ended left zero
	obs3 := m.progressOf(e3, time.Now())
	if obs3.InstallStall.ElapsedSeconds != nil || obs3.InstallStall.ElapsedUnknownReason == "" {
		t.Fatalf("a terminal attempt with no Ended must report ElapsedSeconds unknown: %+v", obs3.InstallStall)
	}
}

// council M26/M27/M28b (round 6 mutation re-run at 0c2f536): the
// window-binding path (EventsBeforeWindowStart/EventsAfterWindowEnd and
// their resulting INSUFFICIENT_EVIDENCE trigger) was only ever exercised
// through registryProgress directly, with synthetic windowStart/windowEnd
// arguments -- never through the real progressOf wiring, where
// windowStart/windowEnd come from a real Entry's own Created/Ended. A
// mutant in progressOf's own window computation (e.g. passing the wrong
// time, or no window at all) could still pass every other end-to-end test
// above, since none of them put any real events outside the real window.
// council C3/M05b (progress.go:376): a mutant that always passes `false`
// for changedDuringRead (so npmproxy.log is never reported re-read mid-
// change) survived, because TestRegistryProgressSetsChangedDuringReadFromItsOwnParameter
// calls registryProgress directly with a synthetic bool, and
// TestProgressOfWiresInstallStallEndToEnd's log never actually changes
// during a read. This drives a REAL concurrent writer appending to the
// real npmproxy.log file while progressOf repeatedly reads it, so
// progressFile's own before/after Stat comparison has a real chance to
// observe a genuine mid-read change, through the real call chain -- not a
// parameter asserted in isolation.
func TestProgressOfDetectsARealRegistryLogChangeDuringARead(t *testing.T) {
	m, _, v := openSigning(t, false)
	id := "install-stall-e2e-changed-during-read"
	rec := filepath.Join(v.Root(), attemptsDir, id)
	if err := os.MkdirAll(rec, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(rec, "npmproxy.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 1000)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	e := Entry{Attempt: id, State: StateRunning, Created: time.Now()}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return
		}
		defer f.Close()
		for {
			select {
			case <-stop:
				return
			default:
				f.Write([]byte(strings.Repeat("y", 200) + "\n"))
			}
		}
	}()
	defer func() { close(stop); <-done }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		obs := m.progressOf(e, time.Now())
		if obs.Registry.ChangedDuringRead {
			if obs.InstallStall.RegistryStatus != sourceUnknown {
				t.Fatalf("a registry log that changed mid-read must report RegistryStatus unknown through the real wiring, not %s: %+v", obs.InstallStall.RegistryStatus, obs.InstallStall)
			}
			return // observed a real, end-to-end mid-read change: passed.
		}
	}
	t.Fatal("never observed a real mid-read change to npmproxy.log within 5s of concurrent writing -- ChangedDuringRead must be reachable through the real progressFile/progressOf call chain, not just a synthetic parameter")
}

func TestProgressOfBindsRealRegistryEventsToTheRealWindowEndToEnd(t *testing.T) {
	m, _, v := openSigning(t, false)
	id := "install-stall-e2e-window-binding"
	rec := filepath.Join(v.Root(), attemptsDir, id)
	if err := os.MkdirAll(rec, 0700); err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	ended := created.Add(10 * time.Second)
	log := strings.Join([]string{
		// Before the real Created: must be excluded and counted.
		`{"schema":"pomar.npm-request/v1","request":1,"event":"received","time":"2026-10-18T11:59:50Z"}`,
		// Genuinely in-window.
		`{"schema":"pomar.npm-request/v1","request":2,"event":"received","time":"2026-10-18T12:00:05Z"}`,
		// After the real Ended: must be excluded and counted.
		`{"schema":"pomar.npm-request/v1","request":3,"event":"received","time":"2026-10-18T12:00:20Z"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(rec, "npmproxy.log"), []byte(log), 0600); err != nil {
		t.Fatal(err)
	}
	e := Entry{Attempt: id, State: StateExited, Created: created, Ended: ended} // terminal, real window [created, ended]
	obs := m.progressOf(e, ended.Add(time.Hour))

	if obs.Registry.EventsBeforeWindowStart != 1 {
		t.Fatalf("Registry.EventsBeforeWindowStart = %d, want 1 (real event before the real Created): %+v", obs.Registry.EventsBeforeWindowStart, obs.Registry)
	}
	if obs.Registry.EventsAfterWindowEnd != 1 {
		t.Fatalf("Registry.EventsAfterWindowEnd = %d, want 1 (real event after the real Ended): %+v", obs.Registry.EventsAfterWindowEnd, obs.Registry)
	}
	if obs.InstallStall.EventsBeforeWindowStart != 1 || obs.InstallStall.EventsAfterWindowEnd != 1 {
		t.Fatalf("InstallStall must carry the real window-binding counts through end to end: %+v", obs.InstallStall)
	}
	if obs.InstallStall.Indication != indicationInsufficientEvidence {
		t.Fatalf("indication = %s, want %s: real unbound events against the real window must force it: %+v", obs.InstallStall.Indication, indicationInsufficientEvidence, obs.InstallStall)
	}
}

// pomar's review of 073f8dd: sourceStatusFor must closed-list known-good
// availability values, not treat anything-not-explicitly-bad as ok -- a
// genuinely unrecognized/corrupted value must read unknown.
func TestSourceStatusForTreatsUnrecognizedAvailabilityAsUnknown(t *testing.T) {
	status, reason := sourceStatusFor("SOME_FUTURE_VALUE_THIS_CODE_DOESNT_KNOW", false)
	if status != sourceUnknown {
		t.Fatalf("status = %s, want unknown for an unrecognized availability value", status)
	}
	if reason == "" {
		t.Fatal("must still say why")
	}
	// The two actual known-good values still read ok.
	for _, v := range []string{"AVAILABLE", "NO_OUTPUT_YET"} {
		if status, _ := sourceStatusFor(v, false); status != sourceOK {
			t.Fatalf("status for %q = %s, want ok", v, status)
		}
	}
}

// council M14-M17: each unknown fact must serialize as an explicit JSON
// null, not be omitted (indistinguishable from "never measured"). Checks
// the real marshaled output, not just the Go-level nil pointer.
func TestInstallStallUnknownFactsSerializeAsExplicitNull(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	// Everything unknown at once: no created time, no registry events, no
	// guest output, default threshold.
	d := installStallDiagnostic("att-null", RegistryProgress{Availability: "AVAILABLE", Events: map[string]int{}, Statuses: map[int]int{}},
		ProgressLog{Availability: "AVAILABLE"}, time.Time{}, nil, "window end unknown for this test", base, nil)

	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"elapsed_seconds", "longest_registry_gap_seconds", "trailing_registry_silence_seconds", "guest_quiet_seconds"} {
		v, present := raw[key]
		if !present {
			t.Fatalf("%q must be present in the serialized JSON even when unknown (omitted key, not null): %s", key, b)
		}
		if string(v) != "null" {
			t.Fatalf("%q = %s, want literal null", key, v)
		}
	}
}

// council M02-M04: each of INSUFFICIENT_EVIDENCE's own trigger conditions
// must independently force it, isolated from every other one -- not just
// a combined fixture that happens to also satisfy several at once. Council
// (round 6 mutation re-run at 0c2f536): these fixtures all had
// SendShortCount == 0, so a mutant narrowing INSUFFICIENT_EVIDENCE's
// precedence to apply only when there's no competing evidential fact (the
// exact P1-1 regression, reintroduced for just one trigger at a time)
// would still pass every one of these -- only the single, separately
// combined "insufficient evidence wins over a genuine fact" case in
// TestInstallStallIndications (which uses WindowTruncated specifically)
// would ever catch it, and only for that one trigger. Every trigger here
// now also carries a genuine send_short fact, confirmed still reported
// even though it doesn't win the Indication.
func TestInstallStallEachInsufficientEvidenceTriggerIsIndependent(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	okReg := func(extra RegistryProgress) RegistryProgress {
		extra.Availability = "AVAILABLE"
		return extra
	}
	cleanReg := okReg(RegistryProgress{Events: map[string]int{"send_short": 1}, Statuses: map[int]int{},
		ShortRequests: []ShortRequestEvidence{{Request: 1, Bytes: seconds(0), Reason: "write failed"}},
		FirstEventAt:  at(base, time.Second), LastEventAt: at(base, 2*time.Second)})
	cleanLog := ProgressLog{Availability: "AVAILABLE"}
	we := end(base, 3*time.Second)

	tests := []struct {
		name string
		reg  RegistryProgress
		log  ProgressLog
	}{
		{"log window truncated alone", cleanReg, ProgressLog{Availability: "AVAILABLE", WindowTruncated: true}},
		{"registry window truncated alone", func() RegistryProgress { r := cleanReg; r.WindowTruncated = true; return r }(), cleanLog},
		{"events before window start alone", func() RegistryProgress { r := cleanReg; r.EventsBeforeWindowStart = 1; return r }(), cleanLog},
		{"events after window end alone", func() RegistryProgress { r := cleanReg; r.EventsAfterWindowEnd = 1; return r }(), cleanLog},
		{"events out of order alone", func() RegistryProgress { r := cleanReg; r.EventsOutOfOrder = 1; return r }(), cleanLog},
		{"events in future alone", func() RegistryProgress { r := cleanReg; r.EventsInFuture = 1; return r }(), cleanLog},
		{"log status unknown alone", cleanReg, ProgressLog{Availability: "AVAILABLE", ChangedDuringRead: true}},
		{"registry status unknown alone", func() RegistryProgress { r := cleanReg; r.ChangedDuringRead = true; return r }(), cleanLog},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := installStallDiagnostic("att-trigger", tc.reg, tc.log, base, we, "", *we, nil)
			if d.Indication != indicationInsufficientEvidence {
				t.Fatalf("indication = %s, want %s: this trigger alone must force it even alongside a genuine send_short fact: %+v", d.Indication, indicationInsufficientEvidence, d)
			}
			if d.SendShortCount != 1 {
				t.Fatalf("the send_short fact must still be reported even though it didn't win the indication: %+v", d)
			}
		})
	}
}

// council M02-M04 (continued): the near-threshold trigger must fire from
// EITHER the internal gap OR the trailing silence independently.
func TestInstallStallNearThresholdTriggersFromEitherGapField(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	okReg := func(extra RegistryProgress) RegistryProgress {
		extra.Availability = "AVAILABLE"
		return extra
	}
	t.Run("longest registry gap near threshold", func(t *testing.T) {
		reg := okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
			FirstEventAt: at(base, time.Second), LastEventAt: at(base, 3*time.Second),
			LongestGapSeconds: seconds(65), LongestGapFromEvent: "a", LongestGapFromAt: at(base, time.Second),
			LongestGapToEvent: "b", LongestGapToAt: at(base, 66*time.Second)})
		we := end(base, 4*time.Second)
		d := installStallDiagnostic("att-near-1", reg, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, nil)
		if d.Indication != indicationInsufficientEvidence {
			t.Fatalf("indication = %s: %+v", d.Indication, d)
		}
	})
	t.Run("trailing silence near threshold", func(t *testing.T) {
		reg := okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
			FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second)})
		we := end(base, 67*time.Second) // trailing silence = 65s, near the 60s default
		d := installStallDiagnostic("att-near-2", reg, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, nil)
		if d.Indication != indicationInsufficientEvidence {
			t.Fatalf("indication = %s: %+v", d.Indication, d)
		}
	})
}

// council M31/Tge (round 6 mutation re-run at 0c2f536): the exact
// boundaries of every >/>=/<= comparison in indicationFor must be pinned,
// not just values comfortably inside or outside them -- a mutant that
// flips a strict comparison to inclusive (or back) at exactly one of
// these boundaries would otherwise survive indefinitely.
func TestInstallStallComparisonBoundariesAreExact(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	okReg := func(extra RegistryProgress) RegistryProgress {
		extra.Availability = "AVAILABLE"
		return extra
	}

	t.Run("near-threshold margin is inclusive at the boundary (default threshold, 20% of 60s = 12s)", func(t *testing.T) {
		// Exactly at the margin (72s, diff=12 from the 60s default): must
		// still read as too-close-to-call.
		reg := okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
			FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second),
			LongestGapSeconds: seconds(72), LongestGapFromEvent: "a", LongestGapFromAt: at(base, time.Second),
			LongestGapToEvent: "b", LongestGapToAt: at(base, 73*time.Second)})
		we := end(base, 3*time.Second)
		d := installStallDiagnostic("att-bound-1", reg, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, nil)
		if d.Indication != indicationInsufficientEvidence {
			t.Fatalf("a gap exactly at the margin boundary (diff == margin) must still be too-close-to-call: %+v", d)
		}
		// One second past the margin (73s, diff=13): must clearly read over.
		reg2 := okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
			FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second),
			LongestGapSeconds: seconds(73), LongestGapFromEvent: "a", LongestGapFromAt: at(base, time.Second),
			LongestGapToEvent: "b", LongestGapToAt: at(base, 74*time.Second)})
		d2 := installStallDiagnostic("att-bound-2", reg2, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, nil)
		if d2.Indication != indicationRegistryGapOver {
			t.Fatalf("a gap one second past the margin must read as a confident over-threshold gap, not near: %+v", d2)
		}
		// council C5/M31lo: the margin is symmetric (diff is an absolute
		// value) -- the LOWER edge (48s, diff=12) must be pinned too, not
		// just the upper edge (72s) above.
		reg3 := okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
			FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second),
			LongestGapSeconds: seconds(48), LongestGapFromEvent: "a", LongestGapFromAt: at(base, time.Second),
			LongestGapToEvent: "b", LongestGapToAt: at(base, 49*time.Second)})
		d3 := installStallDiagnostic("att-bound-7", reg3, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, nil)
		if d3.Indication != indicationInsufficientEvidence {
			t.Fatalf("a gap exactly at the LOWER margin boundary (48s, diff == margin) must still be too-close-to-call: %+v", d3)
		}
		reg4 := okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
			FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second),
			LongestGapSeconds: seconds(47), LongestGapFromEvent: "a", LongestGapFromAt: at(base, time.Second),
			LongestGapToEvent: "b", LongestGapToAt: at(base, 48*time.Second)})
		d4 := installStallDiagnostic("att-bound-8", reg4, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, nil)
		if d4.Indication != indicationNoStall {
			t.Fatalf("a gap one second past the LOWER margin (47s, clearly under threshold) must read as a confident NO_STALL_IN_WINDOW, not near: %+v", d4)
		}
	})

	t.Run("registry gap over threshold is a strict boundary (recorded threshold, bypassing near-threshold)", func(t *testing.T) {
		recorded := int64(60)
		reg := okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
			FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second),
			LongestGapSeconds: seconds(60), LongestGapFromEvent: "a", LongestGapFromAt: at(base, time.Second),
			LongestGapToEvent: "b", LongestGapToAt: at(base, 61*time.Second)})
		we := end(base, 3*time.Second)
		dAt := installStallDiagnostic("att-bound-3", reg, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, &recorded)
		if dAt.Indication != indicationNoStall {
			t.Fatalf("a gap exactly equal to the threshold must not read as over it (strict >): %+v", dAt)
		}
		reg2 := reg
		reg2.LongestGapSeconds = seconds(61)
		dOver := installStallDiagnostic("att-bound-4", reg2, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, &recorded)
		if dOver.Indication != indicationRegistryGapOver {
			t.Fatalf("a gap one second over the threshold must read as over it: %+v", dOver)
		}
	})

	t.Run("guest quiet active is an inclusive boundary (recorded threshold)", func(t *testing.T) {
		recorded := int64(60)
		we := end(base, 60*time.Second)
		regActive := okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
			FirstEventAt: at(base, time.Second), LastEventAt: at(base, 59*time.Second), EventsSinceGuestQuiet: 1})
		logAt := ProgressLog{Availability: "AVAILABLE", LastOutputAt: at(base, 0)} // quiet for exactly 60s
		dAt := installStallDiagnostic("att-bound-5", regActive, logAt, base, we, "", *we, &recorded)
		if dAt.Indication != indicationGuestQuietActive {
			t.Fatalf("guest-quiet exactly equal to the threshold (inclusive >=) must still read active: %+v", dAt)
		}
		logUnder := ProgressLog{Availability: "AVAILABLE", LastOutputAt: at(base, time.Second)} // quiet for 59s
		dUnder := installStallDiagnostic("att-bound-6", regActive, logUnder, base, we, "", *we, &recorded)
		if dUnder.Indication == indicationGuestQuietActive {
			t.Fatalf("guest-quiet one second under the threshold must not read active: %+v", dUnder)
		}
	})
}

// council C1/M04 and C2/M03i: the near-threshold and AttemptIntervalUnknown
// triggers were never combined with a genuine send_short fact -- unlike
// the 8 event/status/truncation triggers in
// TestInstallStallEachInsufficientEvidenceTriggerIsIndependent, these two
// live outside that function's fixture set (nearThreshold is computed
// separately; AttemptIntervalUnknown is folded into anyUnbound but was
// only ever exercised alone). A mutant moving either check to apply only
// when there's no competing send_short fact would have survived.
func TestInstallStallNearThresholdAndIntervalUnknownStillWinOverSendShort(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	okReg := func(extra RegistryProgress) RegistryProgress {
		extra.Availability = "AVAILABLE"
		return extra
	}
	sendShort := []ShortRequestEvidence{{Request: 1, Bytes: seconds(0), Reason: "write failed"}}

	t.Run("near-threshold wins over a genuine send_short fact (C1/M04)", func(t *testing.T) {
		reg := okReg(RegistryProgress{Events: map[string]int{"send_short": 1}, Statuses: map[int]int{},
			ShortRequests: sendShort,
			FirstEventAt:  at(base, time.Second), LastEventAt: at(base, 3*time.Second),
			LongestGapSeconds: seconds(65), LongestGapFromEvent: "a", LongestGapFromAt: at(base, time.Second),
			LongestGapToEvent: "b", LongestGapToAt: at(base, 66*time.Second)})
		we := end(base, 4*time.Second)
		d := installStallDiagnostic("att-c1", reg, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, nil)
		if d.Indication != indicationInsufficientEvidence {
			t.Fatalf("indication = %s, want %s: a near-threshold gap must preempt even a genuine send_short fact: %+v", d.Indication, indicationInsufficientEvidence, d)
		}
		if d.SendShortCount != 1 {
			t.Fatalf("the send_short fact must still be reported: %+v", d)
		}
	})

	t.Run("interval-unknown wins over a genuine send_short fact (C2/M03i)", func(t *testing.T) {
		reg := okReg(RegistryProgress{Events: map[string]int{"send_short": 1}, Statuses: map[int]int{},
			ShortRequests: sendShort,
			FirstEventAt:  at(base, time.Second), LastEventAt: at(base, 2*time.Second)})
		invalidEnd := base // before created: an invalid interval
		created := base.Add(10 * time.Second)
		d := installStallDiagnostic("att-c2", reg, ProgressLog{Availability: "AVAILABLE"}, created, &invalidEnd, "", invalidEnd, nil)
		if !d.AttemptIntervalUnknown {
			t.Fatalf("AttemptIntervalUnknown must still be set: %+v", d)
		}
		if d.Indication != indicationInsufficientEvidence {
			t.Fatalf("indication = %s, want %s: an invalid interval must preempt even a genuine send_short fact: %+v", d.Indication, indicationInsufficientEvidence, d)
		}
		if d.SendShortCount != 1 {
			t.Fatalf("the send_short fact must still be reported: %+v", d)
		}
	})
}

// council C6/M18a-d: the 9 distinct *_unknown_reason STRINGS install_stall.go
// itself produces (elapsed: 1; longest-gap: 2; trailing: 3; guest-quiet: 3,
// not counting each field's shared windowEnd==nil case, which reuses the
// caller-supplied windowEndUnknownReason and is exercised by
// TestInstallStallFactsUnknownWhenWindowEndUnknown) were never individually
// pinned to their EXACT text -- a mutant swapping, truncating or
// misattributing any one of them would still pass every existing test,
// which only checked "non-empty".
func TestInstallStallUnknownReasonStringsAreExact(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	okReg := func(extra RegistryProgress) RegistryProgress {
		extra.Availability = "AVAILABLE"
		return extra
	}
	we := end(base, 10*time.Second)

	t.Run("longest-gap: registry status unknown", func(t *testing.T) {
		reg := okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{}, ChangedDuringRead: true})
		d := installStallDiagnostic("att-r1", reg, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, nil)
		if want := "registry status is unknown"; d.LongestRegistryGapUnknownReason != want {
			t.Fatalf("LongestRegistryGapUnknownReason = %q, want %q: %+v", d.LongestRegistryGapUnknownReason, want, d)
		}
	})
	t.Run("longest-gap: fewer than two recognized events", func(t *testing.T) {
		reg := okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
			FirstEventAt: at(base, time.Second), LastEventAt: at(base, time.Second)})
		d := installStallDiagnostic("att-r2", reg, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, nil)
		if want := "fewer than two recognized, in-window events were observed"; d.LongestRegistryGapUnknownReason != want {
			t.Fatalf("LongestRegistryGapUnknownReason = %q, want %q: %+v", d.LongestRegistryGapUnknownReason, want, d)
		}
	})

	t.Run("trailing: registry status unknown", func(t *testing.T) {
		reg := okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{}, ChangedDuringRead: true})
		d := installStallDiagnostic("att-r3", reg, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, nil)
		if want := "registry status is unknown"; d.TrailingRegistrySilenceUnknownReason != want {
			t.Fatalf("TrailingRegistrySilenceUnknownReason = %q, want %q: %+v", d.TrailingRegistrySilenceUnknownReason, want, d)
		}
	})
	t.Run("trailing: no in-window registry event observed", func(t *testing.T) {
		reg := okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{}})
		d := installStallDiagnostic("att-r4", reg, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, nil)
		if want := "no in-window registry event was observed"; d.TrailingRegistrySilenceUnknownReason != want {
			t.Fatalf("TrailingRegistrySilenceUnknownReason = %q, want %q: %+v", d.TrailingRegistrySilenceUnknownReason, want, d)
		}
	})
	t.Run("trailing: window end precedes last observed registry event", func(t *testing.T) {
		reg := okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
			FirstEventAt: at(base, time.Second), LastEventAt: at(base, 20*time.Second)}) // after `we` (base+10s)
		d := installStallDiagnostic("att-r5", reg, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, nil)
		if want := "window end precedes the last observed registry event"; d.TrailingRegistrySilenceUnknownReason != want {
			t.Fatalf("TrailingRegistrySilenceUnknownReason = %q, want %q: %+v", d.TrailingRegistrySilenceUnknownReason, want, d)
		}
	})

	t.Run("guest-quiet: log status unknown", func(t *testing.T) {
		reg := okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
			FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second)})
		d := installStallDiagnostic("att-r6", reg, ProgressLog{Availability: "AVAILABLE", ChangedDuringRead: true}, base, we, "", *we, nil)
		if want := "log status is unknown"; d.GuestQuietUnknownReason != want {
			t.Fatalf("GuestQuietUnknownReason = %q, want %q: %+v", d.GuestQuietUnknownReason, want, d)
		}
	})
	t.Run("guest-quiet: no output observed yet", func(t *testing.T) {
		reg := okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
			FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second)})
		d := installStallDiagnostic("att-r7", reg, ProgressLog{Availability: "AVAILABLE"}, base, we, "", *we, nil)
		if want := "no output has been observed yet"; d.GuestQuietUnknownReason != want {
			t.Fatalf("GuestQuietUnknownReason = %q, want %q: %+v", d.GuestQuietUnknownReason, want, d)
		}
	})
	t.Run("guest-quiet: window end precedes guest's last observed output", func(t *testing.T) {
		reg := okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
			FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second)})
		d := installStallDiagnostic("att-r8", reg, ProgressLog{Availability: "AVAILABLE", LastOutputAt: at(base, 20*time.Second)}, base, we, "", *we, nil) // after `we`
		if want := "window end precedes the guest's last observed output"; d.GuestQuietUnknownReason != want {
			t.Fatalf("GuestQuietUnknownReason = %q, want %q: %+v", d.GuestQuietUnknownReason, want, d)
		}
	})

	t.Run("elapsed: the shared interval-invalid reason is carried through verbatim", func(t *testing.T) {
		reg := okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
			FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second)})
		created := time.Time{} // missing Created
		d := installStallDiagnostic("att-r9", reg, ProgressLog{Availability: "AVAILABLE"}, created, we, "", *we, nil)
		if want := "attempt has no recorded Created time"; d.ElapsedUnknownReason != want {
			t.Fatalf("ElapsedUnknownReason = %q, want %q: %+v", d.ElapsedUnknownReason, want, d)
		}
	})
}

// council M31/Tge: the out-of-order tolerance boundary is also strict --
// exactly outOfOrderTolerance behind the watermark is still ordinary
// jitter, one tick further is not.
func TestRegistryProgressOutOfOrderToleranceBoundaryIsStrict(t *testing.T) {
	now := time.Date(2026, 10, 18, 13, 0, 0, 0, time.UTC)
	anchor := time.Date(2026, 10, 18, 12, 0, 1, 0, time.UTC)

	atTolerance := strings.Join([]string{
		`{"schema":"pomar.npm-request/v1","request":1,"event":"received","time":"` + anchor.Format(time.RFC3339Nano) + `"}`,
		// Exactly outOfOrderTolerance (1s) earlier than the watermark.
		`{"schema":"pomar.npm-request/v1","request":2,"event":"received","time":"` + anchor.Add(-outOfOrderTolerance).Format(time.RFC3339Nano) + `"}`,
	}, "\n") + "\n"
	p := registryProgress([]byte(atTolerance), false, now, nil, false, time.Time{}, nil)
	if p.EventsOutOfOrder != 0 {
		t.Fatalf("exactly at the tolerance boundary must still be accepted (strict >, not >=): %+v", p)
	}

	pastTolerance := strings.Join([]string{
		`{"schema":"pomar.npm-request/v1","request":1,"event":"received","time":"` + anchor.Format(time.RFC3339Nano) + `"}`,
		// One nanosecond past the tolerance.
		`{"schema":"pomar.npm-request/v1","request":2,"event":"received","time":"` + anchor.Add(-outOfOrderTolerance-time.Nanosecond).Format(time.RFC3339Nano) + `"}`,
	}, "\n") + "\n"
	p2 := registryProgress([]byte(pastTolerance), false, now, nil, false, time.Time{}, nil)
	if p2.EventsOutOfOrder != 1 {
		t.Fatalf("one tick past the tolerance boundary must be flagged out of order: %+v", p2)
	}
}

// pomar's review of 909bf31: the AttemptIntervalUnknown trigger (added
// above for windowEnd==nil) must ALSO cover a non-nil but INVALID
// interval -- windowEnd preceding Created, or Created itself missing --
// not just the one case the first version of this fix happened to name.
// Otherwise sources all read ok, nothing is unbound, yet the attempt's
// own interval still isn't actually known, and NO_STALL_IN_WINDOW would
// be read from it anyway.
func TestInstallStallIntervalUnknownAlsoCoversAnInvalidNonNilWindowEnd(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	reg := RegistryProgress{Availability: "AVAILABLE", Events: map[string]int{}, Statuses: map[int]int{},
		FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second)}
	log := ProgressLog{Availability: "AVAILABLE"}

	t.Run("windowEnd precedes Created", func(t *testing.T) {
		created := base.Add(10 * time.Second)
		invalidEnd := base // before created
		d := installStallDiagnostic("att-interval-1", reg, log, created, &invalidEnd, "", invalidEnd, nil)
		if !d.AttemptIntervalUnknown || d.AttemptIntervalUnknownReason == "" {
			t.Fatalf("AttemptIntervalUnknown must be set for a windowEnd preceding Created: %+v", d)
		}
		if d.Indication != indicationInsufficientEvidence {
			t.Fatalf("indication = %s, want %s: an invalid interval must never read as a confident NO_STALL_IN_WINDOW: %+v", d.Indication, indicationInsufficientEvidence, d)
		}
	})
	t.Run("Created itself missing", func(t *testing.T) {
		we := end(base, time.Second)
		d := installStallDiagnostic("att-interval-2", reg, log, time.Time{}, we, "", *we, nil)
		if !d.AttemptIntervalUnknown {
			t.Fatalf("AttemptIntervalUnknown must be set when Created is missing: %+v", d)
		}
		if d.Indication != indicationInsufficientEvidence {
			t.Fatalf("indication = %s, want %s: %+v", d.Indication, indicationInsufficientEvidence, d)
		}
	})
}
