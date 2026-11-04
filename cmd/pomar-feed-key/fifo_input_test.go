package main

import (
	"fmt"
	"github.com/zeroemployeeorg/pomar/internal/releasefeedissuer"
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

func TestIssuerRefusesFIFOSwapAtDescriptorAcquisition(t *testing.T) {
	d := t.TempDir()
	if e := os.WriteFile(filepath.Join(d, "receipt.json"), []byte("synthetic public receipt"), 0600); e != nil {
		t.Fatal(e)
	}
	root, e := os.OpenRoot(d)
	if e != nil {
		t.Fatal(e)
	}
	race := &fifoSwapRoot{Root: root, target: "receipt.json"}
	in := issuanceInput{InputsDirectory: d, Policy: releasefeedissuer.Policy{Files: map[string]string{}}}
	files, receipt, e := readIssueInputsUsingRoot(in, func(string) (artifactRoot, error) { return race, nil })
	if e == nil || files != nil || receipt != nil || !race.swapped || !race.nonblockingTarget || race.unsafeLeafOpen {
		t.Fatal("FIFO substitution was not safely refused", e)
	}
}
