package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/claudeactor"
)

// Every fake process is retained by the fixture owner and reaped even when a
// test fails while its login gate is still closed. Closing the HTTP server or
// deleting a temp directory is not process cleanup.
func fixtureExecutor(t *testing.T, script, dir string, env []string) func([]string) (claudeactor.Process, error) {
	t.Helper()
	var mu sync.Mutex
	var all []*fixtureProcess
	closed := false
	t.Cleanup(func() {
		mu.Lock()
		closed = true
		processes := append([]*fixtureProcess{}, all...)
		mu.Unlock()
		for _, p := range processes {
			p.in.Close()
			select {
			case <-p.done:
				continue
			default:
			}
			syscall.Kill(-p.cmd.Process.Pid, syscall.SIGTERM)
			go p.Wait()
			select {
			case <-p.done:
			case <-time.After(2 * time.Second):
				syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
				select {
				case <-p.done:
				case <-time.After(2 * time.Second):
					t.Errorf("fake login pid%d did not reap", p.cmd.Process.Pid)
				}
			}
		}
	})
	return func(args []string) (claudeactor.Process, error) {
		mu.Lock()
		defer mu.Unlock()
		if closed {
			return nil, errors.New("fixture already closed")
		}
		cmd := exec.Command(script, args...)
		cmd.Dir = dir
		cmd.Env = append([]string{}, env...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		in, e := cmd.StdinPipe()
		if e != nil {
			return nil, e
		}
		out, e := cmd.StdoutPipe()
		if e != nil {
			in.Close()
			return nil, e
		}
		if e = cmd.Start(); e != nil {
			in.Close()
			out.Close()
			return nil, e
		}
		p := &fixtureProcess{cmd: cmd, in: in, out: out, done: make(chan struct{})}
		all = append(all, p)
		return p, nil
	}
}

type fixtureProcess struct {
	cmd  *exec.Cmd
	in   io.WriteCloser
	out  io.ReadCloser
	done chan struct{}
	once sync.Once
	err  error
}

func (p *fixtureProcess) Stdin() io.WriteCloser { return p.in }
func (p *fixtureProcess) Stdout() io.Reader     { return p.out }
func (p *fixtureProcess) Wait() error {
	p.once.Do(func() { p.err = p.cmd.Wait(); close(p.done) })
	return p.err
}
func (p *fixtureProcess) Interrupt() error { return syscall.Kill(-p.cmd.Process.Pid, syscall.SIGINT) }

func TestFixtureCleanupReapsAnUncompletedLogin(t *testing.T) {
	var process *fixtureProcess
	t.Run("closed completion gate", func(t *testing.T) {
		dir := t.TempDir()
		script := filepath.Join(dir, "fake-login")
		// No stdin reader, no natural completion: only the fixture owner's
		// cleanup can end it. exec keeps the process identity unambiguous.
		if err := os.WriteFile(script, []byte("#!/bin/sh\nexec /bin/sleep 300\n"), 0700); err != nil {
			t.Fatal(err)
		}
		start := fixtureExecutor(t, script, dir, []string{"PATH=/usr/bin:/bin"})
		p, err := start(nil)
		if err != nil {
			t.Fatal(err)
		}
		process = p.(*fixtureProcess)
		// Returning early reproduces an assertion/HTTP failure before sign-in
		// completion; no actor Wait or completion request is needed.
	})
	if process == nil {
		t.Fatal("fixture did not start")
	}
	select {
	case <-process.done:
	default:
		t.Fatal("fixture owner did not reap its child")
	}
	if err := syscall.Kill(process.cmd.Process.Pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatal("fixture still alive after cleanup", err)
	}
}
