//go:build darwin

package serviceupgrade

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// codesign treats a bare requirement as a filename. '=' selects inline text.
func inlineRequirement(text string) string { return "=" + text }

func (n *Native) SigningPolicy() string { return n.M.SigningPolicy }

// Never open or chmod ctl.sock. Its parent is the only admission mode changed;
// the descriptor binds that directory even if its pathname is replaced.
func controlDirectoryMode(path string, uid uint32, mode os.FileMode) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("control directory unavailable")
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Uid != uid || st.Mode&0022 != 0 || (mode != 0700 && mode != 0750) {
		return fmt.Errorf("control directory custody refused")
	}
	return syscall.Fchmod(fd, uint32(mode))
}

func archivedBinaries(path string, build Build, uid uint32) error {
	for _, name := range binaries {
		pin := build.Binaries[name]
		b, err := readFile(filepath.Join(path, name), pin.Bytes, uid)
		if err != nil || int64(len(b)) != pin.Bytes || digest(b) != pin.SHA256 {
			return fmt.Errorf("archived %s does not match the original baseline", name)
		}
	}
	return nil
}
