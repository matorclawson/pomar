package codexseat

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/seatterm"
)

const ConsoleUID = 1001

func checkActorIDs() error {
	groups, e := os.Getgroups()
	if e != nil || os.Getuid() != 1000 || os.Geteuid() != 1000 || os.Getgid() != 1000 || os.Getegid() != 1000 || len(groups) != 1 || groups[0] != 1000 {
		return errors.New("native exec requires exact coding UID/GID/groups1000")
	}
	return nil
}

// ServeConsole is a root broker capability, separate from tmux's UID1001.
// Its root-owned socket/parent cannot be replaced by the custodian. The
// custodian can request only this fixed actor, never argv, policy or a UID.
func (s Supervisor) ServeConsole(ln *net.UnixListener) error {
	if os.Geteuid() != 0 {
		return errors.New("console broker requires root custodian")
	}
	for {
		c, e := ln.AcceptUnix()
		if e != nil {
			return e
		}
		go func() {
			defer c.Close()
			uid, e := peerUID(c)
			if e != nil || uid != ConsoleUID {
				return
			}
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			var req [2]byte
			if _, e = io.ReadFull(c, req[:]); e != nil || string(req[:]) != "r\n" {
				return
			}
			c.SetReadDeadline(time.Time{})
			actor := s
			actor.In = c
			actor.Out = c
			if e = actor.Start(); e != nil {
				fmt.Fprintln(c, "\r\nPomar start/resume refused:", e)
			}
		}()
	}
}

// RunConsole is tmux's fixed UID1001 pane program. No root code parses the
// actor's terminal escape stream. Actor and idle console have separate PTYs.
func RunConsole(socket, seat string, in *os.File, out io.Writer) error {
	if os.Getuid() != ConsoleUID || os.Geteuid() != ConsoleUID || os.Getgid() != ConsoleUID || os.Getegid() != ConsoleUID {
		return errors.New("terminal console requires dedicated custodian UID1001")
	}
	for {
		if e := seatterm.FlushInput(in); e != nil {
			return e
		}
		fmt.Fprintf(out, "\r\nPomar Codex seat %s idle. Type r to start/resume.\r\n> ", seat)
		line, e := readCommand(in)
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		if strings.TrimSpace(line) != "r" {
			continue
		}
		c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
		if e != nil {
			return e
		}
		uid, e := peerUID(c)
		if e != nil || uid != 0 {
			c.Close()
			return errors.New("console broker root identity not established")
		}
		saved, e := stty(in, "-g")
		if e != nil {
			c.Close()
			return e
		}
		if _, e = stty(in, "raw", "-echo"); e != nil {
			c.Close()
			return e
		}
		if _, e = c.Write([]byte("r\n")); e != nil {
			stty(in, saved)
			c.Close()
			return e
		}
		// Pollable duplicate lets the input pump be cancelled on actor exit without
		// consuming the next idle command or leaving a second reader behind.
		err := relayConsole(in, out, c)
		c.Close()
		_, restoreErr := stty(in, saved)
		if restoreErr != nil {
			return restoreErr
		}
		if err != nil {
			return err
		}
	}
}
func stty(in *os.File, args ...string) (string, error) {
	c := exec.Command("/usr/bin/stty", args...)
	c.Stdin = in
	c.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	b, e := c.Output()
	return strings.TrimSpace(string(b)), e
}

func relayConsole(in *os.File, out io.Writer, c net.Conn) error {
	tty, e := os.OpenFile("/dev/tty", os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if e != nil {
		return e
	}
	done := make(chan struct{})
	go func() { defer close(done); io.Copy(c, tty) }()
	_, e = io.Copy(out, c)
	tty.SetReadDeadline(time.Now())
	tty.Close()
	<-done
	return e
}

// ExecCustodian is the fixed tmux trampoline, never root or the coding UID.
// Only the immutable, pinned tmux program may be selected.
func ExecCustodian(argv []string) error {
	if os.Getuid() != ConsoleUID || os.Geteuid() != ConsoleUID || os.Getgid() != ConsoleUID || os.Getegid() != ConsoleUID {
		return errors.New("custodian exec requires UID/GID1001")
	}
	groups, e := os.Getgroups()
	if e != nil || len(groups) > 1 || len(groups) == 1 && groups[0] != ConsoleUID {
		return errors.New("custodian supplementary groups refused")
	}
	if len(argv) < 1 || argv[0] != "/usr/bin/tmux" {
		return errors.New("custodian executable is fixed")
	}
	if e := CheckTmux(argv[0]); e != nil {
		return e
	}
	if e := noNewPrivileges(); e != nil {
		return e
	}
	return syscall.Exec(argv[0], argv, os.Environ())
}
