package seatterm

import (
	"os"
	"syscall"
	"unsafe"
)

func setSize(f *os.File, cols, rows uint16) error {
	ws := struct{ rows, cols, x, y uint16 }{rows, cols, 0, 0}
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TIOCSWINSZ, uintptr(unsafe.Pointer(&ws))); e != 0 {
		return e
	}
	return nil
}

// foregroundPgrp asks the kernel which process group the PTY master's own
// slave side currently has, so a stop can confirm a process group is
// genuinely still this session's before signalling it: a pid the OS has
// since reused for an unrelated group (each session is setsid'd, so its
// pgid is its own leader's pid) must never be signalled on this session's
// say-so. A closed or otherwise unreadable master (this session's own PTY,
// already torn down) refuses rather than guesses, same as any other error.
func foregroundPgrp(f *os.File) (int, error) {
	var pgrp int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), syscall.TIOCGPGRP, uintptr(unsafe.Pointer(&pgrp))); e != 0 {
		return 0, e
	}
	return int(pgrp), nil
}

// resize sets the window size through a brief reopen of the terminal side.
// The parent never keeps that side open: if it did, the controlling side
// would never see the end of the terminal's last process.
func resize(tty string, cols, rows uint16) { resizeTTY(tty, cols, rows) }

// resizeTTY is resize, reporting its outcome.
func resizeTTY(tty string, cols, rows uint16) error {
	f, err := os.OpenFile(tty, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return setSize(f, cols, rows)
}
