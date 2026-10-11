package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/capacity"
	"github.com/zeroemployeeorg/pomar/internal/venue"
)

func TestCurrentCapacityCountsAllKnownNonterminalClaims(t *testing.T) {
	m, _ := openAdmission(t, capacity.Host{CPUSlots: 8, MemoryBytes: 20 * capacity.GiB, Budget: true},
		venue.Space{Used: 100 * capacity.GiB, Avail: 900 * capacity.GiB, Shared: true})
	c := capacity.Class{Name: "ci-site", VCPU: 2, MemoryBytes: 8 * capacity.GiB, VMOverheadBytes: capacity.VMOverhead, DiskPeakBytes: 8 * capacity.GiB, Concurrency: 2}
	m.mu.Lock()
	m.t.entries["starting"] = &Entry{Attempt: "starting", State: StateStarting, Class: c}
	m.t.entries["retired"] = &Entry{Attempt: "retired", State: StateStopping, Class: capacity.Class{Name: "retired", VCPU: 4, MemoryBytes: 6 * capacity.GiB, VMOverheadBytes: capacity.VMOverhead, DiskPeakBytes: 3 * capacity.GiB}}
	m.t.entries["ended"] = &Entry{Attempt: "ended", State: StateExited, Class: c}
	m.mu.Unlock()
	got, err := m.Capacity()
	if err != nil || got.Live != 2 || got.Allocation.Reserved.CPUMillicores != 6000 || got.Allocation.Reserved.MemoryBytes != 15661531136 || got.Allocation.Free.CPUMillicores != 2000 {
		t.Fatalf("current capacity: %+v, %v", got, err)
	}
	if got.Coverage != "KNOWN_NONTERMINAL_ATTEMPTS_ONLY" {
		t.Fatal("claimed full native/environment coverage")
	}
}

func TestHTTPRefusalNamesAllResourceDeficits(t *testing.T) {
	m, _ := openAdmission(t, capacity.Host{CPUSlots: 8, MemoryBytes: 20 * capacity.GiB, Budget: true},
		venue.Space{Used: 100 * capacity.GiB, Avail: 900 * capacity.GiB, Shared: true})
	m.mu.Lock()
	m.t.entries["occupied"] = &Entry{Attempt: "occupied", State: StateRunning,
		Class: capacity.Class{Name: "other", VCPU: 8, MemoryBytes: 20 * capacity.GiB}}
	m.mu.Unlock()
	r := httptest.NewRequest("POST", "/v1/attempts", strings.NewReader(`{"id":"extra","command":["true"]}`))
	r = r.WithContext(context.WithValue(r.Context(), callerKey{}, caller{owner: true}))
	w := httptest.NewRecorder()
	m.mux(true).ServeHTTP(w, r)
	var body struct {
		Reason   string             `json:"reason"`
		Failures []capacity.Failure `json:"failures"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusServiceUnavailable || body.Reason != capacity.ReasonHostBudget {
		t.Fatalf("refusal: %d %s, %v", w.Code, w.Body, err)
	}
	if len(body.Failures) != 2 || body.Failures[0].Resource != "CPU_BUDGET" || body.Failures[0].Deficit != 2000 || body.Failures[1].Resource != "MEMORY_BUDGET" || body.Failures[1].Deficit != capacity.CI.MemoryClaim() {
		t.Fatalf("ambiguous host-budget refusal: %+v", body.Failures)
	}
	if _, exists := m.Get("extra"); exists {
		t.Fatal("a numerically refused request created an attempt")
	}
}

// Exercise admission and claim insertion while the test itself holds m.mu.
// This checks accounting under that lock, not whether Start acquires the lock.
// No real helper/VM is started here.
func TestConcurrentClaimsShareBudgetRatherThanAnExclusiveHost(t *testing.T) {
	for _, requests := range []int{2, 32} {
		t.Run(fmt.Sprint(requests), func(t *testing.T) {
			c := capacity.Class{Name: "ci-site", VCPU: 2, MemoryBytes: 8 * capacity.GiB, VMOverheadBytes: capacity.VMOverhead, DiskPeakBytes: 8 * capacity.GiB, Concurrency: 2}
			m, _ := openAdmission(t, capacity.Host{CPUSlots: 8, MemoryBytes: 20 * capacity.GiB, Budget: true},
				venue.Space{Used: 100 * capacity.GiB, Avail: 900 * capacity.GiB, Shared: true}, JobClass{Class: c})
			var wg sync.WaitGroup
			gate := make(chan struct{})
			for i := 0; i < requests; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-gate
					m.mu.Lock()
					defer m.mu.Unlock()
					if err := m.admit(c); err == nil {
						id := fmt.Sprintf("claim-%d", i)
						m.t.entries[id] = &Entry{Attempt: id, State: StateStarting, Class: c, Created: time.Now().UTC()}
					}
				}(i)
			}
			close(gate)
			wg.Wait()
			got, err := m.Capacity()
			if err != nil || got.Live != 2 || got.Allocation.Reserved.CPUMillicores != 4000 || got.Allocation.Reserved.MemoryBytes != 17809014784 {
				t.Fatalf("concurrent claims: %+v, %v", got, err)
			}
			// Entries are reservations, not execution/installation proof.
			if got.Allocation.FitsCurrent != 0 {
				t.Fatal("a third memory claim fit")
			}
		})
	}
}
