package venue

import "syscall"

func (v *Venue) filesystemDetails(s *syscall.Statfs_t) (blockSize int64, device string, shared bool) {
	device = cstr(s.Mntfromname[:])
	var sys syscall.Statfs_t
	shared = true
	if err := v.statfs(SystemData, &sys); err == nil {
		shared = SameContainer(device, cstr(sys.Mntfromname[:]))
	}
	return int64(s.Bsize), device, shared
}

func cstr(b []int8) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}
