// Package sessiond is Pomar's per-user session service on a host (POMAR-CC
// SOW 27, the same session host the guest seat mode will run): named
// programs on PTYs it owns, which outlive every client, with one controller
// at a time and an exact screen on attach. It replaces tmux for programs
// that run natively on the host, before they move into guests.
//
// Its boundaries, as Pomar scoped them:
//   - It is native execution under the OS user that runs it: not guest
//     isolation, and not organisational admission.
//   - Its socket admits only that same user, so it authenticates the OS
//     principal and nothing finer: every program of that user is the same
//     principal to it. Binding a client to a seat or an elder, and any role
//     key, belong to RT and the Architect, and are never kept here.
//   - A restart of the service, or a reboot, doesn't keep its sessions. On
//     start it reconciles what its journal says the previous service held,
//     and says those sessions are out of its reach, never that they exited.
//   - Its journal is metadata only: who did what to which session, when.
//     Screens and input are never journaled, and a screen read is not
//     claimed to be free of secrets: a program can show one.
//   - Installing it as a user service is a separate, reviewed owner
//     operation; nothing here installs anything.
package sessiond

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// EnvRoot names the service's root; without it, DefaultRoot is used.
const EnvRoot = "POMAR_SESSION_ROOT"

// SocketName is the service's socket, in its root.
const SocketName = "sessions.sock"

// DefaultRoot is $POMAR_SESSION_ROOT, or ~/.local/state/pomar/sessions.
func DefaultRoot() (string, error) {
	if r := os.Getenv(EnvRoot); r != "" {
		if !filepath.IsAbs(r) {
			return "", fmt.Errorf("%s must be an absolute path", EnvRoot)
		}
		return filepath.Clean(r), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return "", fmt.Errorf("no home directory: set %s", EnvRoot)
	}
	return filepath.Join(home, ".local", "state", "pomar", "sessions"), nil
}

// PrepareRoot makes the root if it is missing, mode 0700, and refuses one
// that is a link, isn't a directory, isn't owned by this user, or is open
// to its group or others.
func PrepareRoot(root string) error {
	if !filepath.IsAbs(root) {
		return errors.New("the session root must be an absolute path")
	}
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return err
		}
	}
	return CheckRoot(root)
}

// CheckRoot refuses a root that isn't this user's private directory.
func CheckRoot(root string) error {
	fi, err := os.Lstat(root)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("the session root %s is a link; it must be a directory", root)
	case !fi.IsDir():
		return fmt.Errorf("the session root %s isn't a directory", root)
	case !ok || int(st.Uid) != os.Geteuid():
		return fmt.Errorf("the session root %s isn't owned by this user", root)
	case fi.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("the session root %s is open to others (mode %o); want 0700", root, fi.Mode().Perm())
	}
	return nil
}

// lockRoot takes the root's lock, so one service serves a root. The lock
// is the kernel's: it goes with the process, however it ends.
func lockRoot(root string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(root, "serve.lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, ErrServing
	}
	return f, nil
}

// ErrServing is a root another service already serves.
var ErrServing = errors.New("another session service already serves this root")

// canonical resolves the links above root, never root itself, which must
// not be a link: the socket's custody checks want the real path.
func canonical(root string) string {
	if parent, err := filepath.EvalSymlinks(filepath.Dir(root)); err == nil {
		return filepath.Join(parent, filepath.Base(root))
	}
	return root
}
