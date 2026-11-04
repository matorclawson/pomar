package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type fifoSwapRoot struct {
	*os.Root
	target                                     string
	swapped, nonblockingTarget, unsafeLeafOpen bool
}

func (r *fifoSwapRoot) Lstat(name string) (os.FileInfo, error) {
	info, e := r.Root.Lstat(name)
	if e == nil && name == r.target && !r.swapped {
		if e = r.Root.Remove(name); e != nil {
			return nil, e
		}
		if e = syscall.Mkfifo(filepath.Join(r.Root.Name(), name), 0600); e != nil {
			return nil, e
		}
		r.swapped = true
	}
	return info, e
}
func (r *fifoSwapRoot) OpenFile(name string, flags int, mode os.FileMode) (*os.File, error) {
	if name == r.target {
		if flags&syscall.O_NONBLOCK == 0 || flags&syscall.O_NOFOLLOW == 0 {
			r.unsafeLeafOpen = true
			return nil, fmt.Errorf("test prevents a blocking FIFO open")
		}
		r.nonblockingTarget = true
	}
	return r.Root.OpenFile(name, flags, mode)
}

func (r *fifoSwapRoot) Open(name string) (*os.File, error) {
	if name != "." {
		r.unsafeLeafOpen = true
		return nil, fmt.Errorf("test prevents a blocking leaf open")
	}
	return r.Root.Open(name)
}
func TestObserverRefusesFIFOSwapAtDescriptorAcquisition(t *testing.T) {
	d := t.TempDir()
	if e := os.WriteFile(filepath.Join(d, "release.json"), []byte("synthetic public manifest"), 0600); e != nil {
		t.Fatal(e)
	}
	root, e := os.OpenRoot(d)
	if e != nil {
		t.Fatal(e)
	}
	race := &fifoSwapRoot{Root: root, target: "release.json"}
	args := []string{"-inputs", d, "-head", "1111111111111111111111111111111111111111", "-tree", "2222222222222222222222222222222222222222", "-owner-message", "test-owner"}
	var out bytes.Buffer
	e = runUsingRoot(args, &out, func(string) (artifactRoot, error) { return race, nil })
	if e == nil || out.Len() != 0 || !race.swapped || !race.nonblockingTarget || race.unsafeLeafOpen {
		t.Fatal("FIFO substitution was not safely refused", e)
	}
}
