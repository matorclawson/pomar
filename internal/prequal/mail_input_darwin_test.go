package prequal

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/zeroemployeeorg/pomar/internal/hostpolicy"
)

func TestMailInputDarwinRefusesRootAndFileACLs(t *testing.T) {
	for _, targetRoot := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "root"}[targetRoot], func(t *testing.T) {
			root, b, path, data, digest := mailInputFixture(t)
			got, _, e := acquireFixtureMailInput(root, b, "plan.json", int64(len(data)), digest)
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
			got, proof, e := acquireFixtureMailInput(root, b, "plan.json", int64(len(data)), digest)
			requireMailInputRefusal(t, got, proof, e)
		})
	}
}

func TestMailInputDarwinAncestorACLChangeRefuses(t *testing.T) {
	root, b, _, data, digest := mailInputFixture(t)
	parent := filepath.Dir(b.CanonicalPath)
	parentInfo, e := os.Stat(parent)
	if e != nil {
		t.Fatal(e)
	}
	hooks := mailInputHooks{acl: hostpolicy.DescriptorACLSafe, ancestorACL: func(f *os.File) bool {
		info, e := f.Stat()
		if e != nil {
			return false
		}
		if os.SameFile(parentInfo, info) {
			return hostpolicy.DescriptorACLSafe(f)
		}
		return true // Other host ancestors remain a hermetic assumption.
	}}
	if got, _, e := acquireMailInput(root, b, "plan.json", int64(len(data)), digest, hooks); e != nil || len(got) == 0 {
		t.Fatalf("ancestor ACL-free control: %v", e)
	}
	hooks.afterRead = func() {
		if out, e := exec.Command("/bin/chmod", "+a", "everyone allow add_file,delete_child", parent).CombinedOutput(); e != nil {
			t.Fatalf("private ancestor ACL setup: %v %s", e, out)
		}
		t.Cleanup(func() { exec.Command("/bin/chmod", "-N", parent).Run() })
		info, e := os.Stat(parent)
		if e != nil || info.Mode().Perm()&0022 != 0 {
			t.Fatal("ACL setup unexpectedly changed mode bits")
		}
	}
	got, proof, e := acquireMailInput(root, b, "plan.json", int64(len(data)), digest, hooks)
	requireMailInputRefusal(t, got, proof, e)
}
