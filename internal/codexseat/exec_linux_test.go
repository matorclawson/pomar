package codexseat

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
)

// Isolate the irreversible prctl from the test runner. This executes only on
// Linux; compiling this test on macOS is not evidence of kernel enforcement.
func TestNoNewPrivilegesPersistsAcrossExec(t *testing.T) {
	if os.Getenv("POMAR_TEST_NNP") == "1" {
		if err := noNewPrivileges(); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Exec("/proc/self/exe", []string{os.Args[0], "-test.run=^TestReadNoNewPrivileges$"}, []string{"POMAR_TEST_NNP=2"}); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNoNewPrivilegesPersistsAcrossExec$")
	cmd.Env = []string{"POMAR_TEST_NNP=1"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
}

func TestReadNoNewPrivileges(t *testing.T) {
	if os.Getenv("POMAR_TEST_NNP") != "2" {
		t.Skip("exec helper")
	}
	v, _, err := syscall.RawSyscall6(syscall.SYS_PRCTL, 39, 0, 0, 0, 0, 0)
	if err != 0 || v != 1 {
		t.Fatalf("exec lost no_new_privs: %d %v", v, err)
	}
}
