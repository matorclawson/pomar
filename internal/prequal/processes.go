package prequal

import (
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const OwnerGuestInventoryKind = "owner_executed_in_guest_no_model"
const HostAfterStopKind = "host_scope_after_stop"

// ProcessSnapshot before stop is owner-executed in the no-model guest's kernel,
// through the pinned root collector and original VM transport. It is not a host
// process view or model-phase qualification. Kind distinguishes that inventory
// from the owning host's post-stop empty scope observation. Exe is full, never
// comm/argv[0]/basename; KernelThread comes from actual kernel flags.
type ProcessSnapshot struct {
	ScopeID string       `json:"scope_id"`
	Kind    string       `json:"inventory_kind"`
	Rows    []ProcessRow `json:"rows"`
}
type ProcessRow struct {
	PID          int      `json:"pid"`
	UID          int      `json:"uid"`
	Exe          string   `json:"exe"`
	KernelThread bool     `json:"kernel_thread"`
	Args         []string `json:"args,omitempty"`
}

func allowedProcess(p ProcessRow) bool {
	if p.PID < 1 || p.UID < 0 {
		return false
	}
	if p.KernelThread {
		return p.UID == 0 && p.Exe == "" && len(p.Args) == 0
	}
	if !filepath.IsAbs(p.Exe) || filepath.Clean(p.Exe) != p.Exe {
		return false
	}
	if p.Exe == "/pomar/shim" {
		return p.UID == 0 && slices.Equal(p.Args, mailShimArgs())
	}
	switch p.Exe {
	case "/sbin/init", "/sbin/vminitd", "/bin/sleep", "/usr/bin/sleep", "/bin/ps", "/usr/bin/ps":
		return p.UID == 0
	case "/pomar/isolation-probe":
		// The awaited probe completed before either pre-stop inventory.
		return false
	case "/pomar/d1-driver":
		// Mail Exec has completed before either process view. Any lingering
		// UID1000 driver is unexpected, even with otherwise correct mail args.
		return p.UID == 0 && len(p.Args) == 5 && p.Args[0] == "/pomar/d1-driver" && p.Args[1] == "-mode" && p.Args[2] == "processes" && p.Args[3] == "-scope" && p.Args[4] != ""
	default:
		return false
	}
}
func validateProcesses(s ProcessSnapshot, scope string) error {
	if s.Kind != OwnerGuestInventoryKind || scope == "" || s.ScopeID != scope || len(s.Rows) == 0 || len(s.Rows) > 65536 {
		return errors.New("actual bounded owner process inventory required")
	}
	seen := map[int]bool{}
	shims, collectors := 0, 0
	for _, p := range s.Rows {
		if seen[p.PID] || !allowedProcess(p) || p.Exe == "/pomar/d1-driver" && p.UID == 0 && p.Args[4] != scope {
			return errors.New("owner process outside closed executable/uid allowlist")
		}
		seen[p.PID] = true
		if p.Exe == "/pomar/shim" {
			shims++
		}
		if p.Exe == "/pomar/d1-driver" {
			collectors++
		}
	}
	if shims != 1 || collectors != 1 {
		return errors.New("exactly one live shim and root collector required")
	}
	return nil
}
func validateGuestProcesses(raw []byte, host ProcessSnapshot) error {
	if err := validateProcesses(host, host.ScopeID); err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > 1<<20 {
		return errors.New("bounded guest process view required")
	}
	byPID := map[int]ProcessRow{}
	for _, p := range host.Rows {
		byPID[p.PID] = p
	}
	seen := map[int]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 3 {
			return errors.New("malformed guest process view")
		}
		pid, pe := strconv.Atoi(f[0])
		uid, ue := strconv.Atoi(f[1])
		actual, known := byPID[pid]
		if pe != nil || ue != nil || seen[pid] {
			return errors.New("malformed/duplicate guest pid")
		}
		seen[pid] = true
		if strings.HasPrefix(f[2], "[") {
			// Kernel identity comes from the owner's metadata, never brackets alone.
			if !known || !actual.KernelThread || actual.UID != uid || !allowedProcess(actual) || !strings.HasSuffix(f[len(f)-1], "]") {
				return errors.New("unverified guest kernel view")
			}
		} else {
			observed := ProcessRow{PID: pid, UID: uid, Exe: f[2]}
			// Infrastructure args are authoritative only in the paired root
			// proc inventory; guest ps text alone cannot authorize them.
			if known && actual.Exe == observed.Exe {
				observed.Args = actual.Args
			}
			if observed.Exe == "/pomar/d1-driver" || !allowedProcess(observed) || (known && (actual.KernelThread || actual.UID != uid || actual.Exe != observed.Exe)) {
				return errors.New("guest executable truncated/spoofed/not allowlisted")
			}
		}

	}
	for _, p := range host.Rows {
		if p.Exe == "/pomar/shim" && !seen[p.PID] {
			return errors.New("guest view omits live shim")
		}
	}
	if len(seen) == 0 {
		return errors.New("empty guest view")
	}
	return nil
}
