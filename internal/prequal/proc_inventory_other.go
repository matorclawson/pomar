//go:build !linux

package prequal

import (
	"context"
	"errors"
)

// CollectLinuxProcessSnapshot refuses non-Linux hosts without inspecting them.
func CollectLinuxProcessSnapshot(context.Context, string) (ProcessSnapshot, error) {
	return ProcessSnapshot{}, errors.New("process collector requires Linux root")
}
