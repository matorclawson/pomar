package codexseat

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type ProcessWitness struct {
	PID        int    `json:"pid"`
	Command    string `json:"command"`
	StartTicks string `json:"start_ticks_since_boot"`
}

// Process-table observation is from the custodian, not a coding-user lock or
// self-report. Unreadable/disappearing entries fail closed. This VM dedicates
// UID1000 to its coding scope: a remaining server is a reason to hold, not kill.
func codingProcesses(proc string, uid uint32) ([]ProcessWitness, error) {
	entries, err := os.ReadDir(proc)
	if err != nil {
		return nil, err
	}
	out := []ProcessWitness{}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		data, err := os.ReadFile(filepath.Join(proc, entry.Name(), "status"))
		if err != nil {
			return nil, ErrHeld
		}
		found, match := false, false
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "Uid:") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) != 5 {
				return nil, ErrHeld
			}
			found = true
			for _, field := range fields[1:] {
				n, e := strconv.ParseUint(field, 10, 32)
				if e != nil {
					return nil, ErrHeld
				}
				if uint32(n) == uid {
					match = true
				}
			}
		}
		if !found {
			return nil, ErrHeld
		}
		if match {
			p, e := processWitness(proc, pid)
			if e != nil {
				return nil, ErrHeld
			}
			out = append(out, p)
		}
	}
	return out, nil
}
func noCodingProcesses(proc string, uid uint32) error {
	p, err := codingProcesses(proc, uid)
	if err != nil {
		return err
	}
	if len(p) > 0 {
		return fmt.Errorf("%w: pid=%d command=%s start_ticks=%s", ErrActorRunning, p[0].PID, p[0].Command, p[0].StartTicks)
	}
	return nil
}
func processWitness(proc string, pid int) (ProcessWitness, error) {
	data, err := os.ReadFile(filepath.Join(proc, strconv.Itoa(pid), "stat"))
	if err != nil {
		return ProcessWitness{}, err
	}
	str := string(data)
	a, b := strings.IndexByte(str, '('), strings.LastIndexByte(str, ')')
	if a < 0 || b <= a {
		return ProcessWitness{}, ErrHeld
	}
	fields := strings.Fields(str[b+1:])
	if len(fields) < 20 {
		return ProcessWitness{}, ErrHeld
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return ProcessWitness{}, ErrHeld
	}
	return ProcessWitness{PID: pid, Command: str[a+1 : b], StartTicks: fields[19]}, nil
}
func immutableExecutable(path string) error {
	if err := immutableParents(path); err != nil {
		return err
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0022 != 0 || fi.Mode().Perm()&0111 == 0 {
		return errors.New("guest trampoline custody refused")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return errors.New("guest trampoline must be root-owned")
	}
	return nil
}
func (s Supervisor) writeFenceHolder() error {
	// Internal test fixtures are non-Linux; native paths must supply /proc.
	if os.Geteuid() != 0 {
		return nil
	}
	holder, err := processWitness("/proc", os.Getpid())
	if err != nil {
		return err
	}
	data, err := json.Marshal(holder)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.StateDir, "actor-holder.json"), data, 0600)
}

// InspectFence is owner-only and read-only. A retained holder is named only
// when PID and boot-relative start time still match. Scope processes are the
// authoritative reset/start refusal even if the original supervisor died.
func (s Supervisor) InspectFence() (map[string]any, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("fence inspection requires the VM owner")
	}
	if err := immutableParents(filepath.Join(s.StateDir, "actor.lock")); err != nil {
		return nil, err
	}
	if err := ownedDir(s.StateDir, 0); err != nil {
		return nil, err
	}
	processes, err := codingProcesses("/proc", 1000)
	if err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(s.StateDir, "actor.lock"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	busy := false
	if err == nil {
		defer lock.Close()
		e := syscall.Flock(int(lock.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
		if e == nil {
			syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		} else if errors.Is(e, syscall.EWOULDBLOCK) {
			busy = true
		} else {
			return nil, e
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	var holder *ProcessWitness
	data, err := os.ReadFile(filepath.Join(s.StateDir, "actor-holder.json"))
	if err == nil {
		var saved ProcessWitness
		if json.Unmarshal(data, &saved) != nil {
			return nil, ErrHeld
		}
		current, e := processWitness("/proc", saved.PID)
		if busy && e == nil && current.StartTicks == saved.StartTicks {
			holder = &current
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return map[string]any{"holder": holder, "fence_busy": busy, "coding_processes": processes, "start_time_unit": "ticks since this guest boot", "effects": "UNKNOWN_NOT_INFERRED"}, nil
}

// Fixed guest broker helpers; they grant nothing to the coding user.
func CheckCustodianDirectory(path string) error {
	if err := ownedDir(path, 0); err != nil {
		return err
	}
	return immutableParents(filepath.Join(path, "actor.lock"))
}
func CheckCustodianExecutable(path string) error { return immutableExecutable(path) }
