package prequal

import (
	"os"
	"os/exec"
	"testing"
)

func TestMailInputDarwinRefusesRootAndFileACLs(t *testing.T) {
	for _, targetRoot := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "root"}[targetRoot], func(t *testing.T) {
			root, b, path, data, digest := mailInputFixture(t)
			got, _, e := AcquireMailInput(root, b, "plan.json", int64(len(data)), digest)
			if e != nil || len(got) == 0 {
				t.Fatalf("ACL-free control: %v", e)
			}
			target, ace := path, "everyone allow write"
			if targetRoot {
				target, ace = b.CanonicalPath, "everyone allow add_file,delete_child"
			}
			if output, e := exec.Command("/bin/chmod", "+a", ace, target).CombinedOutput(); e != nil {
				t.Fatalf("private fixture ACL setup: %v %s", e, output)
			}
			t.Cleanup(func() { exec.Command("/bin/chmod", "-N", target).Run() })
			info, e := os.Stat(target)
			if e != nil || info.Mode().Perm()&0022 != 0 {
				t.Fatal("ACL fixture changed write mode bits")
			}
			got, proof, e := AcquireMailInput(root, b, "plan.json", int64(len(data)), digest)
			requireMailInputRefusal(t, got, proof, e)
		})
	}
}
