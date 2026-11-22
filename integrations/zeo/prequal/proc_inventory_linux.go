package prequal

import (
	"context"
	"errors"
	"os"
	"syscall"
)

// CollectLinuxProcessSnapshot reads the current Linux PID namespace's fixed
// procfs as root. The owner adapter must bind that namespace and this collector
// to the original VM scope; scope is a label, not proof of that binding. This is
// a conservative point-in-time view, not evidence of absence between samples.
// The internal d1-driver processes mode invokes this reader; a concrete owner
// adapter must still establish the actual VM namespace/scope binding.
func CollectLinuxProcessSnapshot(ctx context.Context, scope string) (ProcessSnapshot, error) {
	if os.Geteuid() != 0 {
		return ProcessSnapshot{}, errors.New("process collector requires Linux root")
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs("/proc", &st); err != nil {
		return ProcessSnapshot{}, err
	}
	if st.Type != 0x9fa0 {
		return ProcessSnapshot{}, errors.New("fixed /proc is not procfs")
	}
	return collectProc(ctx, "/proc", scope, nil)
}
