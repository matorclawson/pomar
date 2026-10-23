//go:build darwin

package serviceupgrade

// sow: pomar-SOW-87. Opt-in actual2195 executable proof, never installed data.
import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/zeroemployeeorg/pomar/internal/manager"
	"github.com/zeroemployeeorg/pomar/internal/smoke"
)

func TestManagerTableRollbackStartsActual2195(t *testing.T) {
	baseline := os.Getenv("POMAR_ROLLBACK_BASELINE_PATH")
	if baseline == "" {
		t.Skip("separate exact2195 fixture-start qualification requires POMAR_ROLLBACK_BASELINE_PATH; no installed recovery claimed")
	}
	if !filepath.IsAbs(baseline) {
		t.Fatal("absolute baseline path required")
	}
	raw, err := readFile(baseline, 512<<20, 0)
	if err != nil || digest(raw) != "0d88e3a8c446d8d98d425f2b6eb5c9a6508510b639a35b2366f55780326729e7" {
		t.Fatal("independently pinned installed2195 executable required", err)
	}
	root, err := os.MkdirTemp(os.TempDir(), "rb-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if len(manager.SocketPath(root)) >= 104 {
		t.Fatal("baseline fixture requires an approved shorter TMPDIR")
	}
	_, target, archive, pin, before, original := migratedManagerTableAt(t, root)
	kernel := []byte("table-only fixture: deliberately not a bootable kernel\n")
	if err := os.MkdirAll(filepath.Join(root, "kernels"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "kernels", smoke.KernelName), kernel, 0600); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(root, "unused-fixture-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 99\n"), 0700); err != nil {
		t.Fatal(err)
	}
	check := func(wantStart bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, baseline, "manager", "-root", root, "-host-bin", helper, "-kernel-sha256", digest(kernel), "-budget-vcpu", "1", "-budget-memory-gib", "1")
		cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + root, "TMPDIR=" + root, "LC_ALL=C"}
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.WaitDelay = time.Second
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		finished := false
		stop := func() {
			if finished {
				return
			}
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
				finished = true
			case <-time.After(time.Second):
				_ = cmd.Process.Kill()
				select {
				case <-done:
					finished = true
				case <-time.After(time.Second):
					t.Error("baseline child reap unconfirmed")
				}
			}
		}
		defer stop()
		if !wantStart {
			select {
			case err := <-done:
				finished = true
				if err == nil || !strings.Contains(output.String(), "cannot unmarshal object") {
					t.Fatal("omitted-table negative did not fail at the actual legacy decoder", err, output.String())
				}
			case <-ctx.Done():
				stop()
				t.Fatal("baseline decoder refusal was not bounded")
			}
			return
		}
		client := manager.NewClient(root)
		for {
			var entries []manager.Entry
			err := client.DoContext(ctx, "GET", "/v1/attempts", nil, &entries)
			if err == nil {
				if len(entries) != 1 || entries[0].Attempt != "original" || entries[0].ExitCode == nil || *entries[0].ExitCode != 0 {
					t.Fatal("unexpected fixture history")
				}
				stop()
				return
			}
			select {
			case err := <-done:
				finished = true
				t.Fatal("baseline failed before table read", err, output.String())
			case <-ctx.Done():
				stop()
				t.Fatal("baseline readiness/read not confirmed")
			case <-time.After(25 * time.Millisecond):
			}
		}
	}
	// Same real baseline must reject migrated v2 before restore, not merely fail
	// some unrelated setup predicate. The restored original then starts and lists.
	check(false)
	uid := uint32(os.Getuid())
	if err := restoreManagerTable(target, archive, pin, uid, uid, before); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(restored, original) {
		t.Fatal("exact snapshot not restored", err)
	}
	check(true)
}
