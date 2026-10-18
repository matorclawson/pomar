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
	created := time.Now().Add(-30 * time.Second)

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

	e := Entry{Attempt: id, State: StateRunning, Created: created}
	obs := m.progressOf(e, time.Now())
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
// a combined fixture that happens to also satisfy several at once.
func TestInstallStallEachInsufficientEvidenceTriggerIsIndependent(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	okReg := func(extra RegistryProgress) RegistryProgress {
		extra.Availability = "AVAILABLE"
		return extra
	}
	cleanReg := okReg(RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
		FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second)})
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
				t.Fatalf("indication = %s, want %s: this trigger alone must force it: %+v", d.Indication, indicationInsufficientEvidence, d)
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
