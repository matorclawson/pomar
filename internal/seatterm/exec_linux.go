package seatterm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// checkExpectedSHA256 opens path once, hashes it, and refuses on a
// mismatch. On a match, it never lets cmd re-open or re-resolve path at
// exec time: the opened file is handed to the child as an inherited
// descriptor (cmd.ExtraFiles), and cmd.Path becomes that descriptor's
// /proc/self/fd entry, which the kernel resolves to the exact inode
// already opened and hashed, never a name. A file replaced at path after
// this check returns can't be what actually runs: the window this check
// closes is the gap between reading the bytes and exec'ing them, which is
// genuinely zero here, not merely small.
func checkExpectedSHA256(cmd *exec.Cmd, path, expected string) error {
	if expected == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return fmt.Errorf("%s isn't a regular file", path)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		f.Close()
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != expected {
		f.Close()
		return fmt.Errorf("%s hashes to %s, not the expected %s; refusing to launch", path, got, expected)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return err
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, f)
	// ExtraFiles start at fd 3 in the child (0, 1, 2 are stdin/stdout/stderr).
	cmd.Path = fmt.Sprintf("/proc/self/fd/%d", 3+len(cmd.ExtraFiles)-1)
	return nil
}
