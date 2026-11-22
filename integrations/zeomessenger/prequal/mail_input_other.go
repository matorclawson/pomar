//go:build !darwin && !linux

package prequal

import "syscall"

func mailInputChangeTime(*syscall.Stat_t) (int64, int64, bool) {
	return 0, 0, false
}
