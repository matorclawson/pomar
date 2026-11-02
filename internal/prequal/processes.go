package prequal

import (
	"errors"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcessSnapshot must come from the owner adapter's actual pid/uid/executable
// inventory of the owned scope, independently of guest ps output. Exe is the
// full executable path, never comm, argv[0], a basename or a truncated name.
// KernelThread is derived by that trusted collector, never from [name] text.
type ProcessSnapshot struct {
	ScopeID string       `json:"scope_id"`
	Rows    []ProcessRow `json:"rows"`
}
type ProcessRow struct {
	PID          int    `json:"pid"`
	UID          int    `json:"uid"`
	Exe          string `json:"exe"`
	KernelThread bool   `json:"kernel_thread"`
}

func allowedProcess(p ProcessRow) bool {
	if p.PID < 1 || p.UID < 0 {
		return false
	}
	if p.KernelThread {
		return p.UID == 0 && p.Exe == ""
	}
	if !filepath.IsAbs(p.Exe) || filepath.Clean(p.Exe) != p.Exe {
		return false
	}
	switch p.Exe {
	case "/sbin/init", "/sbin/vminitd", "/bin/sleep", "/usr/bin/sleep", "/bin/ps", "/usr/bin/ps":
		return p.UID == 0
	case "/pomar/isolation-probe", "/pomar/d1-driver":
		return p.UID == 1000
	default:
		return false
	}
}
func validateProcesses(s ProcessSnapshot, scope string) error {
	if scope == "" || s.ScopeID != scope || len(s.Rows) == 0 || len(s.Rows) > 65536 {
		return errors.New("actual bounded owner process inventory required")
	}
	seen := map[int]bool{}
	for _, p := range s.Rows {
		if seen[p.PID] || !allowedProcess(p) {
			return errors.New("owner process outside closed executable/uid allowlist")
		}
		seen[p.PID] = true
	}
	return nil
}
func validateGuestProcesses(raw []byte, host ProcessSnapshot) error {
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
			if !allowedProcess(observed) || (known && (actual.KernelThread || actual.UID != uid || actual.Exe != observed.Exe)) {
				return errors.New("guest executable truncated/spoofed/not allowlisted")
			}
		}

	}
	if len(seen) == 0 {
		return errors.New("empty guest view")
	}
	return nil
}
