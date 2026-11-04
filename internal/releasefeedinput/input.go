// Package releasefeedinput acquires bounded regular artifact snapshots without
// blocking on a special file substituted after the initial metadata read.
package releasefeedinput

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

const MaxBytes = int64(32 << 20)

type Root interface {
	Lstat(string) (os.FileInfo, error)
	OpenFile(string, int, os.FileMode) (*os.File, error)
}

// ReadRegular holds a descriptor, checks its type, identity and size before
// reading, and refuses leaf replacement. No-follow is combined with explicit
// leaf checks because a capability-root path resolver can resolve symlinks.
func ReadRegular(root Root, name string, max int64) (raw []byte, err error) {
	if max < 1 || max > MaxBytes {
		return nil, fmt.Errorf("input bound invalid")
	}
	before, e := root.Lstat(name)
	if e != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > max {
		return nil, fmt.Errorf("input leaf metadata invalid")
	}
	f, e := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, fmt.Errorf("input descriptor unavailable")
	}
	defer func() {
		if e := f.Close(); e != nil && err == nil {
			raw = nil
			err = fmt.Errorf("input descriptor close failed")
		}
	}()
	actual, e := f.Stat()
	if e != nil || !actual.Mode().IsRegular() || actual.Size() < 0 || actual.Size() > max || actual.Size() != before.Size() || !os.SameFile(before, actual) {
		return nil, fmt.Errorf("input descriptor metadata or identity changed")
	}
	leaf, e := root.Lstat(name)
	if e != nil || !leaf.Mode().IsRegular() || !os.SameFile(leaf, actual) {
		return nil, fmt.Errorf("input leaf replaced before read")
	}
	raw, e = io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(raw)) > max || int64(len(raw)) != actual.Size() {
		return nil, fmt.Errorf("input read incomplete or excessive")
	}
	after, e := f.Stat()
	if e != nil || !after.Mode().IsRegular() || after.Size() != actual.Size() || !os.SameFile(actual, after) {
		return nil, fmt.Errorf("input changed during read")
	}
	leaf, e = root.Lstat(name)
	if e != nil || !leaf.Mode().IsRegular() || !os.SameFile(leaf, after) {
		return nil, fmt.Errorf("input leaf replaced during read")
	}
	return raw, nil
}
