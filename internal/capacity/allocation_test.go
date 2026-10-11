package capacity

import (
	"math"
	"testing"
)

func currentClasses() (Class, Class) {
	return Class{Name: "ci-site", VCPU: 2, MemoryBytes: 8 * GiB, VMOverheadBytes: VMOverhead, DiskPeakBytes: 8 * GiB, Concurrency: 2},
		Class{Name: "ci-core", VCPU: 4, MemoryBytes: 6 * GiB, VMOverheadBytes: VMOverhead, DiskPeakBytes: 3 * GiB, Concurrency: 2}
}

func TestCurrentFitUsesResourcesAcrossClasses(t *testing.T) {
	site, core := currentClasses()
	h := Host{CPUSlots: 8, MemoryBytes: 20 * GiB, Budget: true}
	d := Disk{Used: 100 * GiB, Avail: 900 * GiB, Shared: true}
	for _, c := range []Class{site, core} {
		if err := Admit(c, []Class{c}, h, d); err != nil {
			t.Fatalf("two fitting %s jobs: %v", c.Name, err)
		}
	}
	a, err := Evaluate(core, []Class{site}, h, d)
	if err != nil || a.FitsCurrent != 1 || len(a.Failures) != 0 {
		t.Fatalf("one core beside site: %+v, %v", a, err)
	}
	a, err = Evaluate(core, []Class{site, core}, h, d)
	if err != nil {
		t.Fatal(err)
	}
	if a.Reserved.CPUMillicores != 6000 || a.Reserved.MemoryBytes != 15661531136 || a.Reserved.DiskBytes != 31*GiB {
		t.Fatalf("mixed claims: %+v", a)
	}
	if a.Free.CPUMillicores != 2000 || a.Free.MemoryBytes != 5813305344 || a.FitsCurrent != 0 {
		t.Fatalf("mixed free: %+v", a)
	}
	if len(a.Failures) != 2 || a.Failures[0].Resource != "CPU_BUDGET" || a.Failures[0].Deficit != 2000 || a.Failures[1].Resource != "MEMORY_BUDGET" || a.Failures[1].Deficit != 943718400 {
		t.Fatalf("third job exact deficits: %+v", a.Failures)
	}
	if a.Failures[0].Reason != ReasonHostBudget || a.Failures[1].Reason != ReasonHostBudget {
		t.Fatal("legacy refusal reason changed")
	}
}

func TestCurrentFitClassLimitIsPerHostAndClass(t *testing.T) {
	site, core := currentClasses()
	h := Host{CPUSlots: 32, MemoryBytes: 128 * GiB}
	d := Disk{Avail: 1000 * GiB}
	a, err := Evaluate(core, []Class{site, site}, h, d)
	if err != nil || a.FitsCurrent != 2 {
		t.Fatalf("other class is not exclusive: %+v, %v", a, err)
	}
	a, err = Evaluate(site, []Class{site, site}, h, d)
	if err != nil || len(a.Failures) != 1 || a.Failures[0].Resource != "CLASS_LIMIT" || a.Failures[0].Deficit != 1 {
		t.Fatalf("per-class ceiling: %+v, %v", a, err)
	}
	// This function receives only one host's claims. Another host's occupied
	// class has no authority over this host's independent budget.
	a, err = Evaluate(site, nil, h, d)
	if err != nil || a.FitsCurrent != 2 {
		t.Fatalf("second host: %+v, %v", a, err)
	}
}

func TestAllocationChecksInvalidAndOverflowCounters(t *testing.T) {
	site, _ := currentClasses()
	h := Host{CPUSlots: 8, MemoryBytes: 20 * GiB}
	d := Disk{Avail: 100 * GiB}
	for _, field := range []string{"memory", "overhead", "disk", "cpu", "concurrency"} {
		c := site
		switch field {
		case "memory":
			c.MemoryBytes = math.MaxInt64
		case "overhead":
			c.VMOverheadBytes = -1
		case "disk":
			c.DiskPeakBytes = math.MaxInt64
		case "cpu":
			c.VCPU = math.MaxInt
		case "concurrency":
			c.Concurrency = -1
		}
		if _, err := Evaluate(c, nil, h, d); err == nil {
			t.Fatalf("invalid %s accepted", field)
		}
	}
	large := site
	large.MemoryBytes, large.VMOverheadBytes = math.MaxInt64/2+1, 0
	if _, err := Evaluate(site, []Class{large, large}, h, d); err == nil {
		t.Fatal("overflowing retained memory accepted")
	}
	if _, err := Evaluate(site, nil, h, Disk{Used: math.MaxInt64, Avail: 1}); err == nil {
		t.Fatal("overflowing disk total accepted")
	}
	// Multiplying the filesystem counters by 100 used to overflow here.
	a, err := Evaluate(site, nil, h, Disk{Used: math.MaxInt64 / 2, Avail: math.MaxInt64 / 2, Shared: true})
	if err != nil || a.FitsCurrent != 2 || a.DiskFloor <= 0 {
		t.Fatalf("large valid disk: %+v, %v", a, err)
	}
}

func TestAllocationRetainsOvercommitAndFillFloor(t *testing.T) {
	site, core := currentClasses()
	h := Host{CPUSlots: 2, MemoryBytes: GiB}
	a, err := Evaluate(site, []Class{core}, h, Disk{Used: 80 * GiB, Avail: 20 * GiB, Shared: true})
	if err != nil || a.Free.CPUMillicores != -2000 || a.Free.MemoryBytes >= 0 || a.FitsCurrent != 0 {
		t.Fatalf("known overcommit must not become free: %+v, %v", a, err)
	}
	if a.DiskFloor != 15*GiB || a.DiskAllowance != 5*GiB {
		t.Fatalf("85%% floor: %+v", a)
	}
	if a.Failures[len(a.Failures)-1].Resource != "DISK_FLOOR" {
		t.Fatalf("floor not separately visible: %+v", a.Failures)
	}
}
