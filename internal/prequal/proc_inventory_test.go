package prequal

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func procStat(pid int, flags, birth uint64) string {
	fields := strings.Fields("S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0")
	fields[6] = strconv.FormatUint(flags, 10)
	fields[19] = strconv.FormatUint(birth, 10)
	return fmt.Sprintf("%d (arbitrary ) name\n) %s\n", pid, strings.Join(fields, " "))
}
func procFixture(t *testing.T, pid, uid int, exe string, kernel bool) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	flags := uint64(0)
	if kernel {
		flags = kernelThreadFlag
	}
	writeProc(t, dir, "stat", procStat(pid, flags, 100))
	writeProc(t, dir, "status", fmt.Sprintf("Name:\tignored\nUid:\t%d %d %d %d\n", uid, uid, uid, uid))
	if exe != "" {
		if e := os.Symlink(exe, filepath.Join(dir, "exe")); e != nil {
			t.Fatal(e)
		}
	}
	return root
}
func writeProc(t *testing.T, dir, name, s string) {
	t.Helper()
	if e := os.WriteFile(filepath.Join(dir, name), []byte(s), 0600); e != nil {
		t.Fatal(e)
	}
}
func TestProcUsesFullExeAndKernelFlag(t *testing.T) {
	for _, tc := range []struct {
		name, exe       string
		uid             int
		kernel, allowed bool
	}{
		{"init", "/sbin/init", 0, false, true},
		{"node not driver", "/usr/bin/node", 1000, false, false},
		{"truncated agent", "/usr/bin/pomar-agent-guest", 1000, false, false},
		{"kernel", "", 0, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := procFixture(t, 42, tc.uid, tc.exe, tc.kernel)
			got, e := collectProc(context.Background(), root, "scope-original", nil)
			if e != nil {
				t.Fatal(e)
			}
			want := ProcessRow{PID: 42, UID: tc.uid, Exe: tc.exe, KernelThread: tc.kernel}
			if len(got.Rows) != 1 || got.Rows[0] != want || got.ScopeID != "scope-original" {
				t.Fatalf("%+v", got)
			}
			if allowedProcess(got.Rows[0]) != tc.allowed {
				t.Fatal("executable policy bypass")
			}
		})
	}
}
func TestProcRefusesUncertainOrChangedIdentity(t *testing.T) {
	cases := map[string]func(*testing.T, string){
		"birth reuse": func(t *testing.T, d string) { writeProc(t, d, "stat", procStat(42, 0, 101)) },
		"uid changed": func(t *testing.T, d string) { writeProc(t, d, "status", "Uid: 1000 1000 1000 1000\n") },
		"exe changed": func(t *testing.T, d string) {
			if e := os.Remove(filepath.Join(d, "exe")); e != nil {
				t.Fatal(e)
			}
			if e := os.Symlink("/usr/bin/node", filepath.Join(d, "exe")); e != nil {
				t.Fatal(e)
			}
		},
		"vanished": func(t *testing.T, d string) {
			if e := os.RemoveAll(d); e != nil {
				t.Fatal(e)
			}
		},
		"added process": func(t *testing.T, d string) {
			if e := os.Mkdir(filepath.Join(filepath.Dir(d), "43"), 0700); e != nil {
				t.Fatal(e)
			}
		},
		"kernel flag changed": func(t *testing.T, d string) {
			writeProc(t, d, "stat", procStat(42, kernelThreadFlag, 100))
			if e := os.Remove(filepath.Join(d, "exe")); e != nil {
				t.Fatal(e)
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			root := procFixture(t, 42, 0, "/sbin/init", false)
			got, e := collectProc(context.Background(), root, "scope-original", func(pid int) error { change(t, filepath.Join(root, strconv.Itoa(pid))); return nil })
			if e == nil || len(got.Rows) != 0 || got.ScopeID != "" {
				t.Fatalf("uncertain view accepted: %+v %v", got, e)
			}
		})
	}
}
func TestProcMalformedViewsFailClosed(t *testing.T) {
	cases := map[string]func(*testing.T, string){
		"comm spoof no kernel bit": func(t *testing.T, d string) { os.Remove(filepath.Join(d, "exe")) },
		"kernel with executable":   func(t *testing.T, d string) { writeProc(t, d, "stat", procStat(42, kernelThreadFlag, 100)) },
		"kernel nonroot": func(t *testing.T, d string) {
			writeProc(t, d, "stat", procStat(42, kernelThreadFlag, 100))
			writeProc(t, d, "status", "Uid: 1000 1000 1000 1000\n")
			os.Remove(filepath.Join(d, "exe"))
		},
		"pid mismatch":  func(t *testing.T, d string) { writeProc(t, d, "stat", procStat(43, 0, 100)) },
		"short stat":    func(t *testing.T, d string) { writeProc(t, d, "stat", "42 (name) S 0\n") },
		"duplicate uid": func(t *testing.T, d string) { writeProc(t, d, "status", "Uid: 0 0 0 0\nUid: 0 0 0 0\n") },
		"unequal uid":   func(t *testing.T, d string) { writeProc(t, d, "status", "Uid: 0 1000 0 0\n") },
		"missing uid":   func(t *testing.T, d string) { writeProc(t, d, "status", "Name: init\n") },
		"oversize":      func(t *testing.T, d string) { writeProc(t, d, "status", strings.Repeat("x", maxProcMetadata+1)) },
		"symlink metadata": func(t *testing.T, d string) {
			os.Remove(filepath.Join(d, "stat"))
			if e := os.Symlink("status", filepath.Join(d, "stat")); e != nil {
				t.Fatal(e)
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			root := procFixture(t, 42, 0, "/sbin/init", false)
			change(t, filepath.Join(root, "42"))
			if got, e := collectProc(context.Background(), root, "scope", nil); e == nil || len(got.Rows) != 0 {
				t.Fatalf("accepted malformed %+v %v", got, e)
			}
		})
	}
}
func TestProcCancellationAndHostRefusal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := collectProc(ctx, "/must-not-open", "scope", nil); e != context.Canceled {
		t.Fatalf("%v", e)
	}
	root := procFixture(t, 42, 0, "/sbin/init", false)
	ctx, cancel = context.WithCancel(context.Background())
	if _, e := collectProc(ctx, root, "scope", func(int) error { cancel(); return nil }); e != context.Canceled {
		t.Fatalf("%v", e)
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		if _, e := CollectLinuxProcessSnapshot(context.Background(), "scope"); e == nil {
			t.Fatal("host accepted")
		}
	}
}

func TestProcSortedInventoryAndSymlinkPIDRefusal(t *testing.T) {
	root := procFixture(t, 42, 0, "/sbin/init", false)
	dir := filepath.Join(root, "2")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	writeProc(t, dir, "stat", procStat(2, kernelThreadFlag, 1))
	writeProc(t, dir, "status", "Uid: 0 0 0 0\n")
	got, e := collectProc(context.Background(), root, "original", nil)
	if e != nil || len(got.Rows) != 2 || got.Rows[0].PID != 2 || got.Rows[1].PID != 42 {
		t.Fatalf("%+v %v", got, e)
	}
	if e := os.Symlink("42", filepath.Join(root, "43")); e != nil {
		t.Fatal(e)
	}
	if _, e := collectProc(context.Background(), root, "original", nil); e == nil {
		t.Fatal("symlink pid accepted")
	}
}

func TestProcZombieRequiresExplicitOwnerReap(t *testing.T) {
	root := procFixture(t, 42, 0, "", false)
	dir := filepath.Join(root, "42")
	writeProc(t, dir, "stat", strings.Replace(procStat(42, 0, 100), ") S ", ") Z ", 1))
	got, e := collectProc(context.Background(), root, "original", nil)
	if e == nil || !strings.Contains(e.Error(), "requires owner reap") || len(got.Rows) != 0 {
		t.Fatalf("zombie silently accepted or dropped: %+v %v", got, e)
	}
}
