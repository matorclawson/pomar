package releasefeedissuer

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

var entryName = regexp.MustCompile(`^[0-9]{6}-[0-9a-f]{12}$`)

// CheckPublicDirectory is the platform check required by Council A3. The
// command fixes the actual root; tests supply independent temporary directories.
func CheckPublicDirectory(path string, uid int) error {
	info, e := os.Lstat(path)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0755 {
		return fmt.Errorf("public directory must be real and not group/other writable")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (int(st.Uid) != 0 && int(st.Uid) != uid) {
		return fmt.Errorf("public directory owner invalid")
	}
	cmd := exec.Command("/bin/ls", "-lde", path)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	raw, e := cmd.Output()
	if e != nil || len(strings.Split(strings.TrimSpace(string(raw)), "\n")) != 1 {
		return fmt.Errorf("public directory ACL absent-state not verified")
	}
	return nil
}
func syncDirectory(root *os.Root) error {
	f, e := root.Open(".")
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}

// Publish publishes a completed bundle atomically and never replaces an entry.
// The caller fixes base and custodian UID and authenticates the policy. Any
// partial stage is retained; the next invocation refuses it for reconciliation.
func Publish(base string, uid int, b Bundle) error {
	if !entryName.MatchString(b.EntryID) {
		return fmt.Errorf("invalid entry identity")
	}
	lane := ""
	switch b.Purpose {
	case "production":
		lane = "entries"
	case "rehearsal":
		lane = "rehearsal"
	default:
		return fmt.Errorf("invalid publication purpose")
	}
	// Validate all fixed descendants, including trust, before every publication.
	for _, p := range []string{base, filepath.Join(base, "entries"), filepath.Join(base, "trust"), filepath.Join(base, "rehearsal")} {
		if e := CheckPublicDirectory(p, uid); e != nil {
			return e
		}
	}
	baseRoot, e := os.OpenRoot(base)
	if e != nil {
		return e
	}
	defer baseRoot.Close()
	lock, e := baseRoot.OpenFile(".publication.lock", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return fmt.Errorf("publication predecessor held; reconcile")
	}
	if _, e = lock.WriteString(b.Purpose + "/" + b.EntryID + "\n"); e == nil {
		e = lock.Sync()
	}
	ce := lock.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if e = syncDirectory(baseRoot); e != nil {
		return e
	}
	// Failed/unknown publications retain this durable global lock. The fixed
	// custodian has no other directory-writer operation; administrator changes
	// require reconciliation. Thus an absent destination cannot appear between
	// the check and rename through another admitted publisher.
	root, e := os.OpenRoot(filepath.Join(base, lane))
	if e != nil {
		return e
	}
	defer root.Close()
	// Only the custodian can write this checked parent. Exclusive staging and
	// pre-rename destination check preserve never-replace behavior for this fixed
	// sequential issuer; the outer sequence-intent lock excludes concurrent issue.
	if _, e := root.Lstat(b.EntryID); !os.IsNotExist(e) {
		return fmt.Errorf("entry already exists or cannot be observed")
	}
	stage := ".pending-" + b.EntryID
	if e := root.Mkdir(stage, 0755); e != nil {
		return fmt.Errorf("pending issue exists or unavailable; reconcile")
	}
	if e := syncDirectory(root); e != nil {
		return e
	}
	sub, e := root.OpenRoot(stage)
	if e != nil {
		return e
	}
	defer sub.Close()
	for name, raw := range b.Files {
		if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,199}$`).MatchString(name) {
			return fmt.Errorf("invalid public filename")
		}
		file, e := sub.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if e != nil {
			return e
		}
		n, e := file.Write(raw)
		if e == nil && n != len(raw) {
			e = io.ErrShortWrite
		}
		if e == nil {
			e = file.Chmod(0644)
		}
		if e == nil {
			e = file.Sync()
		}
		ce := file.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
	}
	if e := syncDirectory(sub); e != nil {
		return e
	}
	if _, e := root.Lstat(b.EntryID); !os.IsNotExist(e) {
		return fmt.Errorf("destination appeared; retain pending issue")
	}
	if e := root.Rename(stage, b.EntryID); e != nil {
		return e
	}
	if e := syncDirectory(root); e != nil {
		return e
	}
	final, e := root.OpenRoot(b.EntryID)
	if e != nil {
		return e
	}
	defer final.Close()
	for n, expected := range b.Files {
		f, e := final.Open(n)
		if e != nil {
			return e
		}
		raw, e := io.ReadAll(io.LimitReader(f, int64(len(expected))+1))
		ce := f.Close()
		if e != nil || ce != nil || !bytes.Equal(raw, expected) {
			return fmt.Errorf("published readback mismatch")
		}
	}
	if e := baseRoot.Remove(".publication.lock"); e != nil {
		return e
	}
	return syncDirectory(baseRoot)
}
