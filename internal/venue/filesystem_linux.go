package venue

import "syscall"

func (v *Venue) filesystemDetails(s *syscall.Statfs_t) (blockSize int64, device string, shared bool) {
	// Linux reports space in fragment units. Some filesystems leave that size
	// unset, so fall back to the reported block size.
	blockSize = int64(s.Frsize)
	if blockSize == 0 {
		blockSize = int64(s.Bsize)
	}
	// statfs does not identify a mount source on Linux. Keep the fill floor
	// in effect since we cannot establish a separate filesystem here.
	return blockSize, "", true
}
