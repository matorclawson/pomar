package codexseat

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"syscall"
)

func hardenActor() error {
	if err := checkActorIDs(); err != nil {
		return err
	}
	return noNewPrivileges()
}
func noNewPrivileges() error {
	// prctl is per-thread. Keep the set/readback/native exec on this exact
	// OS thread; moving the goroutine could otherwise lose the protection.
	// Both production callers exec next, or report failure and exit.
	runtime.LockOSThread()
	const setNoNewPrivs = 38
	const getNoNewPrivs = 39
	if _, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, setNoNewPrivs, 1, 0, 0, 0, 0); e != 0 {
		return e
	}
	value, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, getNoNewPrivs, 0, 0, 0, 0, 0)
	if e != 0 {
		return e
	}
	if value != 1 {
		return errors.New("actor no_new_privs not established")
	}
	return nil
}
func checkTTYPolicy() error {
	b, e := os.ReadFile("/proc/sys/dev/tty/legacy_tiocsti")
	if e != nil || strings.TrimSpace(string(b)) != "0" {
		return errors.New("guest kernel TIOCSTI refusal is not established")
	}
	return nil
}
