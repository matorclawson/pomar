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
// mismatch, same as the Linux version. Darwin has no portable fexecve
// equivalent (no reliable /proc/self/fd-style path that names an open
// descriptor's exact inode for exec), so this does NOT close the full
// check-then-exec window the Linux version does: the check closes the
// file and this returns, and the caller execs cmd.Path by name immediately
// after, with no code of its own in between. A sufficiently privileged,
// precisely timed replacement of the file at path in that gap would still
// run unchecked. That residual window is real and is not claimed closed.
func checkExpectedSHA256(cmd *exec.Cmd, path, expected string) error {
	if expected == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s isn't a regular file", path)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != expected {
		return fmt.Errorf("%s hashes to %s, not the expected %s; refusing to launch", path, got, expected)
	}
	return nil
}
