package prequal

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/zeroemployeeorg/pomar/internal/localclient"
)

var ErrEvidenceCustody = errors.New("qualification evidence custody failed")

var ErrOriginalExists = errors.New("original qualification already exists; inspect it, never retry under a fresh identity")

type journal struct {
	dir  string
	next int
}

func openJournal(parent, operation string) (*journal, error) {
	if !filepath.IsAbs(parent) {
		return nil, errors.New("absolute existing private journal root required")
	}
	real, e := filepath.EvalSymlinks(parent)
	if e != nil || real != parent {
		return nil, errors.New("canonical journal root required")
	}
	if e = localclient.PrivateDir(parent); e != nil {
		return nil, e
	}
	dir := filepath.Join(parent, operation)
	if e = os.Mkdir(dir, 0700); os.IsExist(e) {
		return nil, ErrOriginalExists
	} else if e != nil {
		return nil, e
	}
	if e = syncDir(parent); e != nil {
		return nil, e
	}
	return &journal{dir: dir}, nil
}
func syncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (j *journal) write(name string, value any) error {
	b, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	b = append(b, '\n')
	fd, e := syscall.Open(filepath.Join(j.dir, name), syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), name)
	n, e := f.Write(b)
	if e == nil && n != len(b) {
		e = errors.New("short journal write")
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = syncDir(j.dir)
	}
	return e
}
func (j *journal) event(value any) error {
	j.next++
	if e := j.write(eventName(j.next), value); e != nil {
		return errors.Join(ErrEvidenceCustody, e)
	}
	return nil
}
