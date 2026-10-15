package codexseat

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"syscall"
)

// Debian bookworm tmux3.3a-3 is fixed for CVE-2020-27347. The image package
// pin remains bbf912...; this is its exact extracted arm64 /usr/bin/tmux ELF.
// No package script is run and a version string alone does not satisfy custody.
const TmuxVersion = "tmux 3.3a"
const TmuxSHA256 = "39d32aa901e277eea6eb447eeab472c0cc850ef783711ed26ce3ffee4e3f9011"

func CheckTmux(path string) error {
	if err := immutableExecutable(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, 16<<20))
	if err != nil || n >= 16<<20 || hex.EncodeToString(h.Sum(nil)) != TmuxSHA256 {
		return errors.New("tmux differs from the pinned patched arm64 package")
	}
	return nil
}
