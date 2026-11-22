package prequal

import "syscall"

func mailInputChangeTime(st *syscall.Stat_t) (int64, int64, bool) {
	return st.Ctimespec.Sec, st.Ctimespec.Nsec, true
}
