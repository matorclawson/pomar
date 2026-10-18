package manager

import (
	"testing"
	"time"
)

func seconds(n int64) *int64 { return &n }

func at(base time.Time, d time.Duration) *time.Time {
	t := base.Add(d)
	return &t
}

// council's design review (zc-pcc-collector-v1), amendment 1: a table test
// per class, plus one where two classes are true at once and the fixed
// precedence (PROXY_DELIVERY_SHORT > REGISTRY_GAP_EXCEEDS_FETCH_TIMEOUT >
// GUEST_QUIET_NO_REGISTRY_ACTIVITY > INCONCLUSIVE_WINDOW_TRUNCATED >
// NO_STALL_OBSERVED) decides Classification, while every class's own
// boolean is still reported regardless of which one won. Each case's own
// `now` sits close to its own last event, so only the condition under test
// trips the end-edge gap, not an accident of a shared clock.
func TestInstallStallClassification(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name  string
		reg   RegistryProgress
		log   ProgressLog
		now   time.Time
		check func(t *testing.T, d InstallStallDiagnostic)
	}{
		{
			name: "proxy delivery short",
			reg: RegistryProgress{Events: map[string]int{"send_short": 1}, Statuses: map[int]int{},
				ShortRequests: []ShortRequestEvidence{{Request: 7, Path: "/left-pad/-/left-pad-1.3.0.tgz", Bytes: seconds(100), Want: seconds(10000), Reason: "write failed"}},
				FirstEventAt:  at(base, time.Second), LastEventAt: at(base, 2*time.Second)},
			log: ProgressLog{},
			now: base.Add(3 * time.Second),
			check: func(t *testing.T, d InstallStallDiagnostic) {
				if d.Classification != stallProxyDeliveryShort {
					t.Fatalf("classification = %s, want %s: %+v", d.Classification, stallProxyDeliveryShort, d)
				}
				if !d.ProxyDeliveryShort || d.SendShortCount != 1 || len(d.SendShortRequests) != 1 {
					t.Fatalf("send-short evidence not carried through: %+v", d)
				}
				if d.SendShortRequests[0].Path != "/left-pad/-/left-pad-1.3.0.tgz" {
					t.Fatalf("path not passed through unchanged: %+v", d.SendShortRequests[0])
				}
			},
		},
		{
			name: "registry gap exceeds threshold",
			reg: RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
				FirstEventAt: at(base, time.Second), LastEventAt: at(base, 3*time.Second),
				LongestGapSeconds: seconds(120), LongestGapFromEvent: "upstream_started", LongestGapFromAt: at(base, time.Second),
				LongestGapToEvent: "upstream_connected", LongestGapToAt: at(base, 121*time.Second)},
			log: ProgressLog{},
			now: base.Add(4 * time.Second),
			check: func(t *testing.T, d InstallStallDiagnostic) {
				if d.Classification != stallRegistryGap {
					t.Fatalf("classification = %s, want %s: %+v", d.Classification, stallRegistryGap, d)
				}
				if !d.RegistryGapExceedsThreshold || d.GapSeconds == nil || *d.GapSeconds != 120 {
					t.Fatalf("gap not reported: %+v", d)
				}
				if d.GapFrom != "upstream_started" || d.GapTo != "upstream_connected" {
					t.Fatalf("gap endpoints not named: %+v", d)
				}
			},
		},
		{
			name: "guest quiet, registry still active",
			reg: RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
				FirstEventAt: at(base, time.Second), LastEventAt: at(base, 70*time.Second)},
			log: ProgressLog{LastOutputAt: at(base, 5*time.Second), QuietSeconds: seconds(70)},
			now: base.Add(75 * time.Second), // now - LastOutputAt = 70s, matching QuietSeconds; end-edge (now-LastEventAt) stays a harmless 5s
			check: func(t *testing.T, d InstallStallDiagnostic) {
				if d.Classification != stallGuestQuiet {
					t.Fatalf("classification = %s, want %s: %+v", d.Classification, stallGuestQuiet, d)
				}
				if !d.GuestQuietNoRegistryActivity {
					t.Fatal("guest-quiet boolean not set")
				}
			},
		},
		{
			name: "window truncated, nothing else true",
			reg:  RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{}, WindowTruncated: true},
			log:  ProgressLog{},
			now:  base.Add(300 * time.Second),
			check: func(t *testing.T, d InstallStallDiagnostic) {
				if d.Classification != stallWindowTruncated {
					t.Fatalf("classification = %s, want %s: a truncated window must never read NO_STALL_OBSERVED", d.Classification, stallWindowTruncated)
				}
				if !d.WindowTruncated {
					t.Fatal("truncated boolean not set")
				}
			},
		},
		{
			name: "no stall observed",
			reg: RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
				FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second)},
			log: ProgressLog{},
			now: base.Add(3 * time.Second),
			check: func(t *testing.T, d InstallStallDiagnostic) {
				if d.Classification != stallNoneObserved {
					t.Fatalf("classification = %s, want %s: %+v", d.Classification, stallNoneObserved, d)
				}
				if d.ProxyDeliveryShort || d.RegistryGapExceedsThreshold || d.GuestQuietNoRegistryActivity || d.WindowTruncated {
					t.Fatalf("a boolean is wrongly set on a clean attempt: %+v", d)
				}
			},
		},
		{
			// Two classes true at once: send_short AND a large registry
			// gap. Precedence must choose PROXY_DELIVERY_SHORT, but the
			// gap's own boolean must still be visible to a reader.
			name: "two classes true: precedence picks the higher one, lower boolean still visible",
			reg: RegistryProgress{Events: map[string]int{"send_short": 1}, Statuses: map[int]int{},
				ShortRequests:     []ShortRequestEvidence{{Request: 1, Bytes: seconds(0), Reason: "write failed"}},
				FirstEventAt:      at(base, time.Second),
				LastEventAt:       at(base, 200*time.Second),
				LongestGapSeconds: seconds(150), LongestGapFromEvent: "received", LongestGapFromAt: at(base, 10*time.Second),
				LongestGapToEvent: "completed", LongestGapToAt: at(base, 160*time.Second)},
			log: ProgressLog{},
			now: base.Add(205 * time.Second),
			check: func(t *testing.T, d InstallStallDiagnostic) {
				if d.Classification != stallProxyDeliveryShort {
					t.Fatalf("classification = %s, want %s (precedence)", d.Classification, stallProxyDeliveryShort)
				}
				if !d.ProxyDeliveryShort || !d.RegistryGapExceedsThreshold {
					t.Fatalf("both booleans should be true even though only one became Classification: %+v", d)
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
	reg := RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
		FirstEventAt: at(base, time.Second), LastEventAt: at(base, 50*time.Second),
		LongestGapSeconds: seconds(49), LongestGapFromEvent: "received", LongestGapFromAt: at(base, time.Second),
		LongestGapToEvent: "completed", LongestGapToAt: at(base, 50*time.Second)}
	now := base.Add(60 * time.Second) // end-edge gap stays a harmless 10s either way
	withDefault := installStallDiagnostic("att-2", reg, ProgressLog{}, base, time.Time{}, false, now, nil)
	if withDefault.RegistryGapExceedsThreshold {
		t.Fatalf("a 49s gap must not exceed the 60s default: %+v", withDefault)
	}
	withRecorded := installStallDiagnostic("att-2", reg, ProgressLog{}, base, time.Time{}, false, now, &recorded)
	if withRecorded.ThresholdSource != "recorded" || withRecorded.ThresholdSeconds != 30 {
		t.Fatalf("recorded threshold not used: %+v", withRecorded)
	}
	if !withRecorded.RegistryGapExceedsThreshold {
		t.Fatalf("a recorded, lower threshold should change the outcome: the same 49s gap now exceeds 30s: %+v", withRecorded)
	}
}

// council amendment 3: the edge gaps (Created -> first event, last event ->
// Ended/now) must be covered, not just gaps between events.
func TestInstallStallCoversEdgeGaps(t *testing.T) {
	base := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	t.Run("start edge: a long silence before the first registry event", func(t *testing.T) {
		reg := RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
			FirstEventAt: at(base, 90*time.Second), LastEventAt: at(base, 91*time.Second)}
		d := installStallDiagnostic("att-3", reg, ProgressLog{}, base, time.Time{}, false, base.Add(95*time.Second), nil)
		if !d.RegistryGapExceedsThreshold || d.GapFrom != "attempt_created" {
			t.Fatalf("start-edge gap not detected: %+v", d)
		}
	})
	t.Run("end edge: a long silence after the last registry event, attempt still running", func(t *testing.T) {
		reg := RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
			FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second)}
		d := installStallDiagnostic("att-4", reg, ProgressLog{}, base, time.Time{}, false, base.Add(200*time.Second), nil)
		if !d.RegistryGapExceedsThreshold || d.GapTo != "observed_at" {
			t.Fatalf("end-edge gap (running attempt) not detected: %+v", d)
		}
	})
	t.Run("end edge: terminal attempt uses Ended, not observed_at", func(t *testing.T) {
		reg := RegistryProgress{Events: map[string]int{}, Statuses: map[int]int{},
			FirstEventAt: at(base, time.Second), LastEventAt: at(base, 2*time.Second)}
		ended := base.Add(200 * time.Second)
		// observed_at (now) is far later than Ended; a terminal attempt's
		// own gap must be measured against Ended, not against now.
		d := installStallDiagnostic("att-5", reg, ProgressLog{}, base, ended, true, base.Add(10000*time.Second), nil)
		if !d.RegistryGapExceedsThreshold || d.GapTo != "attempt_ended" || d.GapToAt == nil || !d.GapToAt.Equal(ended) {
			t.Fatalf("terminal attempt should measure the end edge against Ended, not now: %+v", d)
		}
	})
}
