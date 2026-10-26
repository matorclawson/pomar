package seatterm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// checkExpectedSHA256 opens path once, hashes it while copying its bytes
// into a fresh private directory, and execs the copy, never path itself.
// Darwin has no portable fexecve equivalent (no reliable /proc/self/fd-style
// path that names an open descriptor's exact inode for exec), so unlike the
// Linux version this cannot hand the kernel the exact already-hashed inode.
// The copy instead closes the specific gap the council named — path being
// replaced after the check, before the exec that follows — because what
// actually runs is a file nothing but this process ever wrote, not path.
// It is copied from the SAME open descriptor the hash was taken from, never
// a second open of path, so the copy's bytes are exactly what was hashed.
// This narrows, not eliminates, the window: a sufficiently privileged,
// precisely timed replacement of path between this function's first open
// and its first read could still substitute what gets hashed and copied.
// That earlier, narrower window is real and is not claimed closed.
//
// One confirmed, named limit: this cannot pin a macOS platform binary (one
// signed by Apple with a platform identifier, as every binary under
// /bin, /usr/bin and the rest of the signed system volume is). The kernel's
// code-signing enforcement kills a copy of one of those on exec, regardless
// of where the copy lives or that its bytes are byte-identical (confirmed:
// copying /bin/sh and exec'ing the copy exits 137, SIGKILL). An ordinarily
// signed or ad-hoc-signed executable — which is what this exists to pin:
// Pomar's own binaries, Claude Code, Codex — is not a platform binary and
// is unaffected; a shebang script is unaffected too, since the kernel execs
// the named interpreter from its own real path, never the script itself.
// ExpectedSHA256 on a platform binary will fail at exec, not at the check.
//
// A second, confirmed, named limit, checked directly rather than assumed:
// a copy's own argv[0]/executable path moves, from the real install
// location to this private directory, and some installs resolve sibling
// resources relative to that path, not from a fixed location. Checked on
// this host (2026-10): Claude Code's install directory (Homebrew Cask)
// holds nothing beside the single ~207 MB binary -- it is fully
// self-contained, no dylib rpath, nothing to lose by moving. Codex's
// install (`~/.codex/packages/standalone/current/`) is NOT: its own
// `codex-package.json` manifest declares `resourcesDir`/`pathDir` as
// siblings of `bin/`, not of the `codex` binary alone, and that
// `codex-resources`/`codex-path` tree holds a bundled ripgrep and other
// helper binaries (voice, zsh) Codex plausibly locates relative to its
// own installed layout. A copy run from this function's private
// directory has none of those siblings. This was confirmed by reading
// the install layout and its manifest, not by running a copied Codex and
// observing the breakage directly -- whether ripgrep-backed search (or
// the other bundled features) actually fails from a moved copy is a named
// gap in this check, not verified end to end.
//
// Decided: rather than leave that gap live for whatever program turns out
// to need it, preservesInstallPath (Command.PreservesInstallPath) refuses
// the pin outright when set alongside expected, before any file is even
// opened. A silently relocated copy that can't find its own resources
// fails in a way that's hard to diagnose; refusing the combination fails
// loudly instead, at the one point that knows both facts at once.
//
// closeAfterStart is always a no-op here: unlike the Linux version, this
// never hands cmd an inherited descriptor (cmd.Path names a plain path,
// the private copy, not a /proc/self/fd entry), so there is nothing left
// open for the caller to close once Start returns. The signature matches
// the Linux version's so host.go's call site is platform-agnostic.
func checkExpectedSHA256(cmd *exec.Cmd, path, expected string, preservesInstallPath bool) (closeAfterStart func(), err error) {
	if expected == "" {
		return nil, nil
	}
	if preservesInstallPath {
		return nil, fmt.Errorf("%s resolves resources relative to its installed location; pinning it would run a copy with none of them, so the launch refuses rather than relocate it", path)
	}
	pinned, err := copyPinnedExecutable(path, expected, 0, "")
	if err != nil {
		return nil, err
	}
	cmd.Path = pinned
	return nil, nil
}

// bytesRequired==0 preserves the existing entry point's copy semantics.
func copyPinnedExecutable(path, expected string, bytesRequired int64, stagingRoot string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s isn't a regular file", path)
	}
	dir, err := os.MkdirTemp(stagingRoot, "pomar-launch-")
	if err != nil {
		return "", err
	}
	cp, err := os.OpenFile(dir+"/bin", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o500)
	if err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	h := sha256.New()
	var reader io.Reader = f
	if bytesRequired > 0 {
		reader = io.LimitReader(f, bytesRequired+1)
	}
	written, copyErr := io.Copy(io.MultiWriter(h, cp), reader)
	if copyErr != nil || (bytesRequired > 0 && written != bytesRequired) {
		err := copyErr
		if err == nil {
			err = fmt.Errorf("executable size differs from frozen pin")
		}
		cp.Close()
		os.RemoveAll(dir)
		return "", err
	}
	if err := cp.Close(); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != expected {
		os.RemoveAll(dir)
		return "", fmt.Errorf("%s hashes to %s, not the expected %s; refusing to launch", path, got, expected)
	}
	if bytesRequired > 0 {
		// A prepared owner may launch under another already-authorised UID. Never
		// broaden the original executable's read/execute policy, and never grant
		// anyone write permission. The random directory is traversable, not listable.
		if err := os.Chmod(cp.Name(), 0500|(fi.Mode().Perm()&0055)); err != nil {
			os.RemoveAll(dir)
			return "", err
		}
		if err := os.Chmod(dir, 0711); err != nil {
			os.RemoveAll(dir)
			return "", err
		}
	}
	// The copy is left on disk, named uniquely per launch under the OS
	// temp directory (0700, Go's own MkdirTemp default): forensic evidence
	// of exactly what ran, not cleaned up here. Its parent's cleanup is the
	// OS's own temp-directory reaping, the same as everything else under it.
	return cp.Name(), nil
}

// PrepareExecutable prepares one bounded Darwin executable and freezes an
// owner-selected lookup policy. requiredNames and pins must name the same set.
// A Walking85 owner must supply node, npm and git from its complete selected
// closure. No name, PATH or identity is inferred from the host environment.
// This is preparation, not authenticated native admission or containment.
func PrepareExecutable(stagingRoot string, c Command, requiredNames []string, pins []LookupPin) (*PreparedExecutable, error) {
	realRoot, rootErr := filepath.EvalSymlinks(stagingRoot)
	rootInfo, statErr := os.Lstat(stagingRoot)
	if !preparedPath(stagingRoot) || rootErr != nil || realRoot != stagingRoot || statErr != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("explicit canonical owner staging directory required")
	}
	owner, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return nil, fmt.Errorf("staging directory is not owned by the preparer")
	}
	if c.PreservesInstallPath {
		return nil, fmt.Errorf("prepare refuses an original install-path requirement; stage its resources through the owner first")
	}
	if !preparedPath(c.Path) || !preparedDigest(c.ExpectedSHA256) || len(pins) == 0 || len(pins) > 64 || len(requiredNames) != len(pins) {
		return nil, fmt.Errorf("explicit pinned program and bounded complete lookup policy required")
	}
	required := map[string]bool{}
	requiredFold := map[string]bool{}
	for _, name := range requiredNames {
		if !preparedName(name) || requiredFold[strings.ToLower(name)] {
			return nil, fmt.Errorf("invalid or duplicate required lookup name")
		}
		required[name] = true
		requiredFold[strings.ToLower(name)] = true
	}
	frozen := append([]LookupPin(nil), pins...)
	seen := map[string]bool{}
	program := -1
	var total int64
	for i, pin := range frozen {
		name := strings.ToLower(pin.Name)
		if !preparedName(pin.Name) || !required[pin.Name] || seen[name] || !preparedPath(pin.Path) || !preparedDigest(pin.SHA256) || pin.Bytes <= 0 || pin.Bytes > 512<<20 {
			return nil, fmt.Errorf("invalid, missing or duplicate lookup pin")
		}
		seen[name] = true
		total += pin.Bytes
		if total > 1<<30 {
			return nil, fmt.Errorf("lookup executable bytes exceed preparation bound")
		}
		if pin.Path == c.Path {
			if program >= 0 || pin.SHA256 != c.ExpectedSHA256 {
				return nil, fmt.Errorf("program lookup identity must be unique and match its expected pin")
			}
			program = i
		}
		if _, err := verifyLookupFile(pin); err != nil {
			return nil, err
		}
	}
	if program < 0 {
		return nil, fmt.Errorf("required policy must include the pinned program lookup")
	}
	path, err := copyPinnedExecutable(c.Path, c.ExpectedSHA256, frozen[program].Bytes, stagingRoot)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	final := filepath.Join(dir, frozen[program].Name)
	if err := os.Rename(path, final); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	frozen[program].Path = final
	fi, err := os.Lstat(final)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	di, err := os.Lstat(dir)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	held, err := os.OpenFile(final, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	heldInfo, err := held.Stat()
	if err != nil || !os.SameFile(fi, heldInfo) {
		held.Close()
		os.RemoveAll(dir)
		return nil, fmt.Errorf("prepared executable changed before identity was held")
	}
	st := &preparedExecutableState{id: newID(), path: final, lookups: frozen}
	// Cleanup refuses a replaced directory or executable rather than deleting a
	// new occupant. A failure remains visible to the owner as uncertain cleanup.
	st.cleanup = func() error {
		defer held.Close()
		d, e := os.Lstat(dir)
		if e != nil || !os.SameFile(di, d) || d.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("prepared staging directory changed; retained for owner reconciliation")
		}
		f, e := os.Lstat(final)
		if e != nil || !os.SameFile(fi, f) {
			return fmt.Errorf("prepared executable changed; retained for owner reconciliation")
		}
		entries, e := os.ReadDir(dir)
		if e != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(final) {
			return fmt.Errorf("prepared staging directory has unexpected contents; retained")
		}
		if e = os.Remove(final); e != nil {
			return e
		}
		return os.Remove(dir)
	}
	st.validate = func(command Command) error {
		if command.Path != final || command.ExpectedSHA256 != c.ExpectedSHA256 {
			return fmt.Errorf("prepared path and nonempty expected pin must match frozen identity")
		}
		d, e := os.Lstat(dir)
		if e != nil || !os.SameFile(di, d) || d.Mode() != di.Mode() {
			return fmt.Errorf("prepared directory identity changed")
		}
		f, e := verifyLookupFile(frozen[program])
		if e != nil {
			return e
		}
		if !os.SameFile(fi, f) || f.Mode() != fi.Mode() {
			return fmt.Errorf("prepared executable inode or mode changed")
		}
		return verifyPreparedLookups(command.Env, frozen)
	}
	return &PreparedExecutable{state: st}, nil
}

func preparedName(s string) bool {
	if len(s) == 0 || len(s) > 64 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.+-", r)) {
			return false
		}
	}
	return true
}
func preparedPath(s string) bool {
	return filepath.IsAbs(s) && filepath.Clean(s) == s && len(s) > 1 && len(s) <= 4096 && !strings.ContainsAny(s, "\x00\r\n:")
}
func preparedDigest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == sha256.Size && strings.ToLower(s) == s
}
func verifyLookupFile(pin LookupPin) (os.FileInfo, error) {
	real, e := filepath.EvalSymlinks(pin.Path)
	if e != nil || real != pin.Path {
		return nil, fmt.Errorf("lookup pin is not a canonical physical file: %s", pin.Name)
	}
	before, e := os.Lstat(pin.Path)
	if e != nil {
		return nil, e
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !before.Mode().IsRegular() || before.Mode().Perm()&0111 == 0 || before.Mode().Perm()&0022 != 0 || before.Size() != pin.Bytes || !ok || stat.Nlink != 1 {
		return nil, fmt.Errorf("lookup file identity/type/size refused: %s", pin.Name)
	}
	f, e := os.OpenFile(pin.Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("lookup file replaced at open: %s", pin.Name)
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, pin.Bytes+1))
	if e != nil || n != pin.Bytes || hex.EncodeToString(h.Sum(nil)) != pin.SHA256 {
		return nil, fmt.Errorf("lookup executable bytes differ: %s", pin.Name)
	}
	after, e := os.Lstat(pin.Path)
	if e != nil || !os.SameFile(opened, after) || after.Size() != pin.Bytes || after.Mode() != opened.Mode() {
		return nil, fmt.Errorf("lookup file replaced during verification: %s", pin.Name)
	}
	return after, nil
}
func verifyPreparedLookups(env []string, pins []LookupPin) error {
	path := ""
	found := false
	for _, v := range env {
		if strings.ContainsRune(v, 0) {
			return fmt.Errorf("NUL in explicit environment")
		}
		if strings.HasPrefix(v, "PATH=") {
			if found {
				return fmt.Errorf("duplicate PATH in explicit environment")
			}
			found = true
			path = strings.TrimPrefix(v, "PATH=")
		}
	}
	dirs := strings.Split(path, ":")
	if !found || len(dirs) > 64 {
		return fmt.Errorf("bounded explicit PATH required")
	}
	for _, d := range dirs {
		real, e := filepath.EvalSymlinks(d)
		info, statErr := os.Stat(d)
		if statErr != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("PATH directory is not protected from other writers")
		}
		if !preparedPath(d) || e != nil || real != d {
			return fmt.Errorf("PATH directories must be canonical and absolute")
		}
	}
	// Two passes detect a shadow introduced while the selected files are hashed.
	// Immutable directory/file custody is still required at the owner boundary;
	// this cannot defeat a privileged writer racing the final check and exec.
	for pass := 0; pass < 2; pass++ {
		for _, pin := range pins {
			selected := ""
			for _, d := range dirs {
				candidate := filepath.Join(d, pin.Name)
				_, e := os.Lstat(candidate)
				if os.IsNotExist(e) {
					continue
				}
				if e != nil {
					return e
				}
				real, e := filepath.EvalSymlinks(candidate)
				if e != nil {
					return e
				}
				selected = real
				break
			}
			if selected != pin.Path {
				return fmt.Errorf("PATH shadows or omits selected executable: %s", pin.Name)
			}
			if _, e := verifyLookupFile(pin); e != nil {
				return e
			}
		}
	}
	return nil
}
