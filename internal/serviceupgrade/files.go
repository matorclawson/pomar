package serviceupgrade

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Open nonblocking and no-follow, then inspect the descriptor before reading.
// This rejects FIFOs, hardlinks, mutable ownership and a replaced pathname.
func readFile(path string, maximum int64, uid uint32) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("required regular file unavailable")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || (uid != ^uint32(0) && st.Uid != uid) || st.Nlink != 1 || before.Mode().Perm()&0022 != 0 || before.Size() <= 0 || before.Size() > maximum {
		return nil, fmt.Errorf("file custody or size refused")
	}
	b, err := io.ReadAll(io.LimitReader(f, maximum+1))
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || len(b) > int(maximum) || int64(len(b)) != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, fmt.Errorf("file changed while reading")
	}
	return b, nil
}
func pinnedFile(path string, pin FilePin) ([]byte, error) {
	return pinnedOwnedFile(path, pin, 0)
}

func pinnedOwnedFile(path string, pin FilePin, uid uint32) ([]byte, error) {
	b, err := readFile(path, pin.Bytes, uid)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != pin.Bytes || digest(b) != pin.SHA256 {
		return nil, fmt.Errorf("file does not match frozen binding")
	}
	return b, nil
}

func directory(path string, uid uint32, mode os.FileMode) error {
	st, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("required directory unavailable")
	}
	meta, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.IsDir() || meta.Uid != uid || (mode != 0 && st.Mode().Perm() != mode) || st.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("directory custody refused")
	}
	return nil
}

// The sole writable ancestor allowed is macOS's root-owned sticky staging
// directory. The selected leaf must itself be root-owned 0700.
func privateRoot(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("absolute canonical private directory required")
	}
	if err := directory(path, 0, 0700); err != nil {
		return err
	}
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		if p == "/private/var/tmp" {
			st, err := os.Lstat(p)
			if err != nil {
				return err
			}
			m, ok := st.Sys().(*syscall.Stat_t)
			if !ok || !st.IsDir() || m.Uid != 0 || st.Mode()&os.ModeSticky == 0 {
				return fmt.Errorf("staging ancestor refused")
			}
		} else if err := directory(p, 0, 0); err != nil {
			return err
		}
		if p == "/" {
			break
		}
	}
	return nil
}
func durableWrite(path string, b []byte, mode os.FileMode) error {
	return durableWriteOwned(path, b, mode, 0)
}

func durableWriteOwned(path string, b []byte, mode os.FileMode, uid uint32) error {
	parent := filepath.Dir(path)
	if err := directory(parent, uid, 0); err != nil {
		return err
	}
	before, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		return fmt.Errorf("write directory replaced while opening")
	}
	meta, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || !opened.IsDir() || meta.Uid != uid || opened.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("opened write directory custody refused")
	}
	// All effects below are relative to this descriptor. A manager-owner rename
	// or ancestor symlink swap cannot redirect a privileged write elsewhere.
	if err := durableWriteIn(root, filepath.Base(path), b, mode, uid); err != nil {
		return err
	}
	after, err := os.Lstat(parent)
	if err != nil || !os.SameFile(opened, after) {
		return fmt.Errorf("write directory replaced; retain recovery uncertainty")
	}
	return nil
}

func durableWriteIn(root *os.Root, name string, b []byte, mode os.FileMode, uid uint32) error {
	tmp := ".pomar-upgrade-pending-" + rand.Text()
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(tmp)
	defer f.Close()
	if uid != uint32(os.Geteuid()) {
		if err = f.Chown(int(uid), -1); err != nil {
			return err
		}
	}
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	written, err := f.Stat()
	if err != nil {
		return err
	}
	linked, err := root.Lstat(tmp)
	if err != nil || !os.SameFile(written, linked) || !linked.Mode().IsRegular() {
		return fmt.Errorf("pending file replaced; write refused")
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = root.Rename(tmp, name); err != nil {
		return err
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
